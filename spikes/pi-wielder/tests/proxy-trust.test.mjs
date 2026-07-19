import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createCollar, SKILL_ID } from '../src/collar.mjs';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { canonicalJson, createReceiptSigner, verifySignedReceipt } from '../src/invocation-journal.mjs';
import {
  assertReceiptMatchesPayment,
  createProxy,
  DEFAULT_PROXY_MODEL_REQUEST_BYTES,
  DEFAULT_PROXY_REQUEST_TIMEOUT_MS,
  DEFAULT_PROXY_RESPONSE_TIMEOUT_MS,
  DEFAULT_PROXY_SKILL_REQUEST_BYTES,
  DEFAULT_PROXY_UPSTREAM_RESPONSE_BYTES,
  loadPinnedCollarTrust,
  startProxy,
} from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { createMockFacilitatorTransport } from '../src/x402-seller.mjs';

function signReceipt(signer, receipt) {
  const receiptHash = crypto.createHash('sha256').update(canonicalJson(receipt)).digest('hex');
  return {
    receipt,
    receiptHash,
    signature: signer.signHash(receiptHash),
    algorithm: signer.algorithm,
    keyId: signer.keyId,
  };
}

const expected = Object.freeze({
  idempotencyKey: 'idem-current',
  requestHash: `sha256:${'1'.repeat(64)}`,
  quoteId: `sha256:${'2'.repeat(64)}`,
  amountAtomic: '250000',
  payer: `0x${'a'.repeat(40)}`,
  settlementReference: `0x${'b'.repeat(64)}`,
  txHash: `0x${'c'.repeat(64)}`,
  httpStatus: 200,
  skillId: 'skill-current',
  resource: 'http://collar.test/invoke/skill-current',
});

function receiptFor(overrides = {}) {
  return {
    schemaVersion: 2,
    revision: 1,
    supersedesReceiptHash: null,
    invocationId: 'inv-current',
    idempotencyKey: expected.idempotencyKey,
    mode: 'external',
    skill: { id: expected.skillId, versionHash: `sha256:${'d'.repeat(64)}` },
    requestHash: expected.requestHash,
    wielderId: expected.payer,
    quote: {
      schemaVersion: 2,
      requestHash: expected.requestHash,
      quoteId: expected.quoteId,
      amountAtomic: expected.amountAtomic,
      currency: 'USDC',
      network: 'base-sepolia',
      resource: expected.resource,
      executionQuote: { schemaVersion: 2, quoteId: expected.quoteId, grossAtomic: expected.amountAtomic },
    },
    payment: {
      state: 'settled',
      payer: expected.payer,
      settlementReference: expected.settlementReference,
      txHash: expected.txHash,
      refundAmountAtomic: null,
    },
    execution: { state: 'succeeded', httpStatus: expected.httpStatus },
    accounting: {
      schemaVersion: 2,
      quoteId: expected.quoteId,
      grossAtomic: expected.amountAtomic,
      allocationState: 'finalized',
    },
    ...overrides,
  };
}

test('proxy startup accepts only an explicitly pinned public key and matching key ID', () => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-public-')));
  const publicKeyFile = path.join(directory, 'collar-public.pem');
  const signer = createReceiptSigner();
  fs.writeFileSync(publicKeyFile, signer.publicKeyPem);
  const trust = loadPinnedCollarTrust({
    COLLAR_PUBLIC_KEY_FILE: publicKeyFile,
    COLLAR_KEY_ID: signer.keyId,
  });
  assert.equal(trust.trustedCollarKeyId, signer.keyId);
  assert.doesNotThrow(() => createProxy({ account: throwawayAccount(), ...trust }));
  assert.throws(() => loadPinnedCollarTrust({ COLLAR_PUBLIC_KEY_FILE: publicKeyFile }), /require/);
  assert.throws(() => loadPinnedCollarTrust({
    COLLAR_PUBLIC_KEY_FILE: publicKeyFile,
    COLLAR_KEY_ID: `sha256:${'0'.repeat(64)}`,
  }), /does not match/);
  assert.throws(() => loadPinnedCollarTrust({
    COLLAR_PUBLIC_KEY_FILE: path.basename(publicKeyFile),
    COLLAR_KEY_ID: signer.keyId,
  }), /absolute/);
  const symlink = path.join(directory, 'collar-link.pem');
  fs.symlinkSync(publicKeyFile, symlink);
  assert.throws(() => loadPinnedCollarTrust({
    COLLAR_PUBLIC_KEY_FILE: symlink,
    COLLAR_KEY_ID: signer.keyId,
  }), /regular non-symlink/);
  assert.throws(() => createProxy({ account: throwawayAccount() }), /pinned Collar/);
  assert.throws(() => createProxy({
    account: throwawayAccount(),
    trustedCollarPublicKeyPem: signer.publicKeyPem,
    trustedCollarKeyId: `sha256:${'0'.repeat(64)}`,
  }), /do not match/);
});

test('proxy constructor options cannot raise secure byte or deadline ceilings', () => {
  const signer = createReceiptSigner();
  const trust = {
    trustedCollarPublicKeyPem: signer.publicKeyPem,
    trustedCollarKeyId: signer.keyId,
  };
  for (const [option, value, ceiling] of [
    ['maxSkillRequestBytes', DEFAULT_PROXY_SKILL_REQUEST_BYTES + 1, DEFAULT_PROXY_SKILL_REQUEST_BYTES],
    ['maxModelRequestBytes', DEFAULT_PROXY_MODEL_REQUEST_BYTES + 1, DEFAULT_PROXY_MODEL_REQUEST_BYTES],
    ['maxUpstreamResponseBytes', DEFAULT_PROXY_UPSTREAM_RESPONSE_BYTES + 1, DEFAULT_PROXY_UPSTREAM_RESPONSE_BYTES],
    ['proxyRequestTimeoutMs', DEFAULT_PROXY_REQUEST_TIMEOUT_MS + 1, DEFAULT_PROXY_REQUEST_TIMEOUT_MS],
    ['proxyResponseTimeoutMs', DEFAULT_PROXY_RESPONSE_TIMEOUT_MS + 1, DEFAULT_PROXY_RESPONSE_TIMEOUT_MS],
  ]) {
    assert.throws(
      () => createProxy({ account: throwawayAccount(), ...trust, [option]: value }),
      new RegExp(`${option} cannot exceed ${ceiling}`),
    );
  }
});

test('a valid signature is insufficient when receipt semantics do not match the paid request', () => {
  const signer = createReceiptSigner();
  const valid = signReceipt(signer, receiptFor());
  assert.equal(verifySignedReceipt(valid, {
    publicKeyPem: signer.publicKeyPem,
    keyId: signer.keyId,
  }), true);
  assert.equal(assertReceiptMatchesPayment(valid, expected).invocationId, 'inv-current');

  const legacyReceipt = receiptFor({
    schemaVersion: 1,
    quote: Object.fromEntries(Object.entries(receiptFor().quote)
      .filter(([key]) => !['schemaVersion', 'executionQuote'].includes(key))),
    accounting: { grossAtomic: expected.amountAtomic, allocationState: 'finalized' },
  });
  assert.equal(assertReceiptMatchesPayment(signReceipt(signer, legacyReceipt), expected).schemaVersion, 1);

  const stale = signReceipt(signer, receiptFor({ idempotencyKey: 'idem-previous' }));
  assert.equal(verifySignedReceipt(stale, {
    publicKeyPem: signer.publicKeyPem,
    keyId: signer.keyId,
  }), true);
  assert.throws(() => assertReceiptMatchesPayment(stale, expected), /does not semantically match/);

  for (const mutation of [
    { payment: { ...receiptFor().payment, state: 'signed' } },
    { execution: { state: 'executing', httpStatus: 200 } },
    { execution: { state: 'succeeded', httpStatus: 500 } },
    { accounting: { grossAtomic: '249999', allocationState: 'finalized' } },
    { quote: { ...receiptFor().quote, resource: 'http://evil.test/invoke/skill-current' } },
    { quote: { ...receiptFor().quote, executionQuote: { ...receiptFor().quote.executionQuote, quoteId: `sha256:${'9'.repeat(64)}` } } },
    { quote: { ...receiptFor().quote, executionQuote: undefined } },
  ]) {
    const bundle = signReceipt(signer, receiptFor(mutation));
    assert.throws(() => assertReceiptMatchesPayment(bundle, expected), /does not semantically match/);
  }
});

test('a settled Skill failure is cached without inventing finalized treasury or Royalty claims', async () => {
  const facilitator = createMockFacilitator();
  const collar = createCollar({
    facilitatorTransport: createMockFacilitatorTransport(
      (url, init) => facilitator.request(url, init),
    ),
    executeSkill: async () => { throw new Error('provider detail must stay inside seller logs'); },
  });
  const proxy = createProxy({
    account: throwawayAccount(),
    collarUrl: 'http://collar.test',
    collarFetch: (url, init) => collar.app.request(url, init),
    gatewayFetch: async () => { throw new Error('model gateway must not run'); },
    trustedCollarPublicKeyPem: collar.journal.signingPublicKeyPem,
    trustedCollarKeyId: collar.journal.signingKeyId,
  });
  const response = await proxy.app.request(`http://proxy.test/invoke/${SKILL_ID}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'settled failure' }),
  });
  assert.equal(response.status, 500);
  const body = await response.json();
  assert.equal(body.receipt.receipt.execution.state, 'failed');
  assert.equal(proxy.ledger.entries.length, 1);
  const [entry] = proxy.ledger.entries;
  assert.equal(entry.view, 'wielder-receipt');
  assert.equal(entry.status, 'failed');
  assert.equal(entry.amountAtomic, '250000');
  assert.equal(entry.receipt.receipt.accounting.allocationState, 'pending_cogs_reconciliation');
  assert.equal(entry.splits, null);
  const rendered = await proxy.app.request('http://proxy.test/ledger');
  assert.equal(rendered.status, 200);
  assert.match(await rendered.text(), /\[failed\]/);
});

test('proxy listener binds only IPv4 loopback and closes cleanly', async () => {
  const signer = createReceiptSigner();
  const proxy = await startProxy({
    account: throwawayAccount(),
    trustedCollarPublicKeyPem: signer.publicKeyPem,
    trustedCollarKeyId: signer.keyId,
  });
  try {
    assert.equal(proxy.address, '127.0.0.1');
    assert.equal(new URL(proxy.url).hostname, '127.0.0.1');
    assert.equal((await fetch(`${proxy.url}/ledger?format=json`)).status, 200);
  } finally {
    await proxy.close();
  }
});

test('unknown Skill fails before payment through both Collar and proxy', async () => {
  let facilitatorCalls = 0;
  let settlementCalls = 0;
  let executionCalls = 0;
  const facilitator = createMockFacilitator();
  const collar = createCollar({
    facilitatorTransport: createMockFacilitatorTransport(async (url, init) => {
      facilitatorCalls += 1;
      if (new URL(url).pathname === '/settle') settlementCalls += 1;
      return facilitator.request(url, init);
    }),
    executeSkill: async () => {
      executionCalls += 1;
      return { output: 'must not run' };
    },
  });
  const unknownUrl = 'http://collar.test/invoke/not-a-known-skill';
  const direct = await collar.app.request(unknownUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'must remain unpaid' }),
  });
  assert.equal(direct.status, 404);
  assert.deepEqual(await direct.json(), { error: "unknown Skill 'not-a-known-skill'" });

  const proxy = createProxy({
    account: throwawayAccount(),
    collarUrl: 'http://collar.test',
    collarFetch: (url, init) => collar.app.request(url, init),
    gatewayFetch: async () => { throw new Error('model gateway must not run'); },
    trustedCollarPublicKeyPem: collar.journal.signingPublicKeyPem,
    trustedCollarKeyId: collar.journal.signingKeyId,
  });
  const forwarded = await proxy.app.request('http://proxy.test/invoke/not-a-known-skill', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'still unpaid' }),
  });
  assert.equal(forwarded.status, 404);
  const forwardedBody = await forwarded.json();
  assert.deepEqual(forwardedBody, { error: "unknown Skill 'not-a-known-skill'" });
  assert.equal('receipt' in forwardedBody, false);
  assert.equal(facilitatorCalls, 0);
  assert.equal(settlementCalls, 0);
  assert.equal(executionCalls, 0);
  assert.equal(collar.journal.events.length, 0);
  assert.equal(proxy.ledger.entries.length, 0);
});

test('proxy rejects a chunked 4097-byte Skill request before any upstream fetch', {
  timeout: 1_000,
}, async () => {
  const signer = createReceiptSigner();
  let upstreamCalls = 0;
  let pulls = 0;
  let cancelled = false;
  const proxy = createProxy({
    account: throwawayAccount(),
    collarFetch: async () => { upstreamCalls += 1; throw new Error('must not fetch'); },
    gatewayFetch: async () => { upstreamCalls += 1; throw new Error('must not fetch'); },
    trustedCollarPublicKeyPem: signer.publicKeyPem,
    trustedCollarKeyId: signer.keyId,
    maxSkillRequestBytes: 4096,
  });
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      if (pulls === 1) controller.enqueue(new Uint8Array(4096));
      else controller.enqueue(new Uint8Array([1]));
    },
    cancel() { cancelled = true; },
  });
  const response = await proxy.app.request(`http://proxy.test/invoke/${SKILL_ID}`, {
    method: 'POST', body, duplex: 'half',
  });
  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), {
    error: 'proxy Skill request exceeds the 4096-byte limit',
    code: 'PROXY_REQUEST_TOO_LARGE',
  });
  assert.equal(cancelled, true);
  assert.equal(upstreamCalls, 0);
  assert.equal(proxy.ledger.entries.length, 0);
});

test('proxy cancels a chunked oversized upstream response before buffering it', {
  timeout: 1_000,
}, async () => {
  const signer = createReceiptSigner();
  let cancelled = false;
  const proxy = createProxy({
    account: throwawayAccount(),
    gatewayFetch: async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(600_000));
        controller.enqueue(new Uint8Array(500_000));
      },
      cancel() { cancelled = true; },
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
    collarFetch: async () => { throw new Error('Collar must not run'); },
    trustedCollarPublicKeyPem: signer.publicKeyPem,
    trustedCollarKeyId: signer.keyId,
    maxUpstreamResponseBytes: 1024 * 1024,
  });
  const response = await proxy.app.request('http://proxy.test/v1/chat/completions', {
    method: 'POST',
    body: JSON.stringify({ model: 'claude-sonnet-4-6', messages: [] }),
  });
  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), {
    error: 'upstream response exceeds the proxy byte limit',
    code: 'UPSTREAM_RESPONSE_TOO_LARGE',
  });
  assert.equal(cancelled, true);
  assert.equal(proxy.ledger.entries.length, 0);
});

test('proxy response deadline stops a slow chunked upstream without leaking its error', {
  timeout: 1_000,
}, async () => {
  const signer = createReceiptSigner();
  let cancelled = false;
  const proxy = createProxy({
    account: throwawayAccount(),
    gatewayFetch: async () => new Response(new ReadableStream({
      pull() { return new Promise(() => {}); },
      cancel() { cancelled = true; },
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
    collarFetch: async () => { throw new Error('Collar must not run'); },
    trustedCollarPublicKeyPem: signer.publicKeyPem,
    trustedCollarKeyId: signer.keyId,
    proxyResponseTimeoutMs: 20,
  });
  const response = await proxy.app.request('http://proxy.test/v1/chat/completions', {
    method: 'POST',
    body: JSON.stringify({ model: 'claude-sonnet-4-6', messages: [] }),
  });
  assert.equal(response.status, 504);
  assert.deepEqual(await response.json(), {
    error: 'upstream response timed out',
    code: 'UPSTREAM_RESPONSE_TIMEOUT',
  });
  assert.equal(cancelled, true);
  assert.equal(proxy.ledger.entries.length, 0);
});

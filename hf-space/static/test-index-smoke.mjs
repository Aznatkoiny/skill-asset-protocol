import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parseHTML } from 'linkedom';

const STATIC_ROOT = new URL('./', import.meta.url);
const LIVE_ENDPOINT = 'https://neverhandedover.com/api/invoke/optimizing-claude-code-prompts';
const LOCAL_URLS = [
  './data/fixture-integrity.json',
  './data/public-demo-allocation.json',
  './data/evidence.json',
];
const VALID_402 = {
  x402Version: 1,
  accepts: [{
    scheme: 'exact',
    network: 'base-sepolia',
    maxAmountRequired: '250000',
    resource: LIVE_ENDPOINT,
    payTo: '0x25005dfac23d4bc45c801eaeb6c8b5a2bab0f189',
    asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  }],
};

function response(value, status = 200) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => String(bytes.length) },
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

async function waitForClick(button) {
  button.click();
  const deadline = Date.now() + 1_000;
  while (button.disabled && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  assert.equal(button.disabled, false);
}

test('actual HTML auto-mounts once and distinguishes valid 402 from JSON 200/500', async (t) => {
  const html = await readFile(new URL('index.html', STATIC_ROOT), 'utf8');
  const { window, document } = parseHTML(html);
  Object.defineProperty(document, 'readyState', { value: 'complete', configurable: true });
  const scripts = [...document.querySelectorAll('script[type="module"]')];
  assert.equal(scripts.length, 1);
  assert.equal(scripts[0].getAttribute('src'), './demo-logic.mjs');
  assert.ok(document.querySelector('#scenario-select'));
  assert.ok(document.querySelector('#check-live-402'));

  const local = new Map(await Promise.all(LOCAL_URLS.map(async (url) => [
    url,
    await readFile(new URL(url.slice(2), STATIC_ROOT)),
  ])));
  let liveStatus = 402;
  const seen = [];
  const fetchStub = async (url) => {
    seen.push(url);
    if (local.has(url)) return response(local.get(url));
    if (url === LIVE_ENDPOINT) {
      if (liveStatus === 402) return response(VALID_402, 402);
      return response({ status: `synthetic-${liveStatus}` }, liveStatus);
    }
    throw new Error(`unstubbed URL: ${url}`);
  };

  const prior = {
    window: globalThis.window,
    document: globalThis.document,
    fetch: globalThis.fetch,
    crypto: globalThis.crypto,
  };
  Object.defineProperties(globalThis, {
    window: { value: window, configurable: true, writable: true },
    document: { value: document, configurable: true, writable: true },
    fetch: { value: fetchStub, configurable: true, writable: true },
    crypto: { value: webcrypto, configurable: true, writable: true },
  });
  t.after(() => {
    for (const [key, value] of Object.entries(prior)) {
      Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
    }
  });

  const module = await import(new URL(`demo-logic.mjs?browser=${Date.now()}`, STATIC_ROOT));
  await module.browserBootstrapPromise;
  assert.equal(document.documentElement.dataset.skillAssetMounted, 'true');
  assert.equal(document.documentElement.dataset.skillAssetMountCount, '1');
  assert.match(document.querySelector('#allocation-output').textContent, /Intra-org/);
  assert.deepEqual(seen.slice(0, 3), LOCAL_URLS);

  const button = document.querySelector('#check-live-402');
  const result = document.querySelector('#live-result');
  await waitForClick(button);
  assert.equal(result.dataset.live, 'true');
  assert.match(result.textContent, /valid live HTTP 402 offer/i);

  liveStatus = 200;
  await waitForClick(button);
  assert.equal(result.dataset.live, 'false');
  assert.match(result.textContent, /did not return a valid 402 offer/i);

  liveStatus = 500;
  await waitForClick(button);
  assert.equal(result.dataset.live, 'false');
  assert.match(result.textContent, /did not return a valid 402 offer/i);
  assert.equal(document.documentElement.dataset.skillAssetMountCount, '1');
});

test('module import outside a browser performs no fetch and exposes null bootstrap', async () => {
  const descriptors = Object.fromEntries(
    ['window', 'document', 'fetch'].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]),
  );
  let fetches = 0;
  try {
    Object.defineProperties(globalThis, {
      window: { value: undefined, configurable: true, writable: true },
      document: { value: undefined, configurable: true, writable: true },
      fetch: { value: () => { fetches += 1; }, configurable: true, writable: true },
    });
    const module = await import(new URL(`demo-logic.mjs?server=${Date.now()}`, STATIC_ROOT));
    assert.equal(module.browserBootstrapPromise, null);
    assert.equal(fetches, 0);
  } finally {
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
});

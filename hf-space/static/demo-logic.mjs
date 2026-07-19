const LIVE_ENDPOINT = 'https://neverhandedover.com/api/invoke/optimizing-claude-code-prompts';
const EXPECTED_PAY_TO = '0x25005dfac23d4bc45c801eaeb6c8b5a2bab0f189';
const EXPECTED_ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const LOCAL_FIXTURE_URLS = Object.freeze([
  './data/fixture-integrity.json',
  './data/public-demo-allocation.json',
  './data/evidence.json',
]);
const FIXTURE_NAMES = Object.freeze(['evidence.json', 'public-demo-allocation.json']);
const ATOMIC_PATTERN = /^(0|[1-9][0-9]*)$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const SHA_PATTERN = /^sha256:[0-9a-f]{64}$/;
const MAX_RESPONSE_BYTES = 65_536;
const RESPONSE_DEADLINE_MILLISECONDS = 5_000;

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length
    && actual.every((key, index) => key === sorted[index]);
}

function decodeJson(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return JSON.parse(text);
  } catch (error) {
    throw new TypeError(`invalid JSON for ${label}`, { cause: error });
  }
}

function abortable(operation, signal) {
  if (signal.aborted) return Promise.reject(signal.reason ?? new Error('response deadline exceeded'));
  return new Promise((resolve, reject) => {
    const aborted = () => reject(signal.reason ?? new Error('response deadline exceeded'));
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(operation).then(
      (value) => {
        signal.removeEventListener('abort', aborted);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', aborted);
        reject(error);
      },
    );
  });
}

async function responseBytes(response, label, { requireOk = true, signal } = {}) {
  if (!response?.body || typeof response.body.getReader !== 'function') {
    throw new TypeError(`${label} response is invalid`);
  }
  if (requireOk && response.ok !== true) throw new TypeError(`${label} request failed`);
  const contentLength = response.headers?.get?.('content-length');
  if (contentLength != null && contentLength !== '') {
    if (!ATOMIC_PATTERN.test(contentLength) || Number(contentLength) > MAX_RESPONSE_BYTES) {
      throw new TypeError(`${label} response is too large`);
    }
  }
  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await abortable(reader.read(), signal);
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError(`${label} response chunk is invalid`);
      if (value.byteLength > MAX_RESPONSE_BYTES - totalBytes) {
        throw new TypeError(`${label} response is too large`);
      }
      chunks.push(Uint8Array.from(value));
      totalBytes += value.byteLength;
    }
  } catch (error) {
    try {
      Promise.resolve(reader.cancel?.(error)).catch(() => {});
    } catch {
      // The original bounded-read error is authoritative.
    }
    throw error;
  } finally {
    reader.releaseLock?.();
  }
  if (totalBytes === 0) {
    throw new TypeError(`${label} response is empty`);
  }
  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function fetchResponseBytes(
  fetchImpl,
  url,
  fetchOptions,
  label,
  { requireOk = true, deadlineMilliseconds = RESPONSE_DEADLINE_MILLISECONDS } = {},
) {
  if (!Number.isInteger(deadlineMilliseconds) || deadlineMilliseconds <= 0) {
    throw new TypeError('response deadline must be a positive integer');
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort(new Error(`${label} response deadline exceeded`));
  }, deadlineMilliseconds);
  try {
    const response = await abortable(fetchImpl(url, {
      ...fetchOptions,
      signal: controller.signal,
    }), controller.signal);
    const bytes = await responseBytes(response, label, { requireOk, signal: controller.signal });
    return Object.freeze({ bytes, status: response.status });
  } catch (error) {
    if (!controller.signal.aborted) controller.abort(error);
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function sha256(bytes, cryptoImpl) {
  if (!cryptoImpl?.subtle || typeof cryptoImpl.subtle.digest !== 'function') {
    throw new TypeError('Web Crypto SHA-256 is unavailable');
  }
  const digest = new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', bytes));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function validateIntegrityManifest(value) {
  if (!hasExactKeys(value, ['schemaVersion', 'generatedBy', 'files'])
      || value.schemaVersion !== 1
      || value.generatedBy !== 'hf-space/scripts/package-space-fixtures.mjs'
      || !hasExactKeys(value.files, FIXTURE_NAMES)) {
    throw new TypeError('packaged fixture integrity mismatch: fixture-integrity.json');
  }
  for (const fileName of FIXTURE_NAMES) {
    const metadata = value.files[fileName];
    if (!hasExactKeys(metadata, ['sha256', 'bytes'])
        || !Number.isSafeInteger(metadata.bytes)
        || metadata.bytes <= 0
        || typeof metadata.sha256 !== 'string'
        || !SHA_PATTERN.test(metadata.sha256)) {
      throw new TypeError('packaged fixture integrity mismatch: fixture-integrity.json');
    }
  }
  return value;
}

function validateAllocationFixture(value) {
  if (!isRecord(value)
      || value.schemaVersion !== 1
      || value.evidenceStatus !== 'synthetic_accounting_illustration'
      || value.defaultScenarioId !== 'intra-org'
      || !Array.isArray(value.scenarios)
      || value.scenarios.length !== 3) {
    throw new TypeError('invalid public demo accounting fixture');
  }
  const expected = new Map([
    ['intra-org', ['internal_invocation_award', 'terminal_product_spike']],
    ['education', ['external_royalty_claim', 'deferred']],
    ['marketplace', ['external_royalty_claim', 'phase_3_optionality']],
  ]);
  const seen = new Set();
  for (const scenario of value.scenarios) {
    if (!isRecord(scenario) || !expected.has(scenario.id) || seen.has(scenario.id)) {
      throw new TypeError('invalid public demo scenario');
    }
    seen.add(scenario.id);
    const [kind, status] = expected.get(scenario.id);
    if (scenario.allocationKind !== kind || scenario.status !== status) {
      throw new TypeError('invalid public demo scenario status');
    }
  }
  if (seen.size !== expected.size) throw new TypeError('missing public demo scenario');
  return value;
}

function validateEvidenceFixture(value) {
  if (!isRecord(value)
      || value.schemaVersion !== 1
      || !isRecord(value.historicalOverhead)
      || value.historicalOverhead.evidenceStatus !== 'historical_unreproducible'
      || value.historicalOverhead.publicationAllowed !== false
      || !Array.isArray(value.historicalSkillLegTransactions)
      || value.historicalSkillLegTransactions.length !== 1
      || !isRecord(value.historicalSkillLegTransactions[0])
      || value.historicalSkillLegTransactions[0].evidenceStatus
        !== 'historical_transaction_receipt_verified') {
    throw new TypeError('invalid public demo evidence fixture');
  }
  return value;
}

export async function loadPackagedFixtures({ fetchImpl, cryptoImpl }) {
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function');
  const fetchOptions = Object.freeze({
    method: 'GET',
    redirect: 'error',
    cache: 'no-store',
    credentials: 'omit',
  });
  const { bytes: integrityBytes } = await fetchResponseBytes(
    fetchImpl,
    LOCAL_FIXTURE_URLS[0],
    fetchOptions,
    'fixture-integrity.json',
  );
  const integrity = validateIntegrityManifest(decodeJson(integrityBytes, 'fixture-integrity.json'));
  const values = Object.create(null);
  const fixtureRequests = [
    ['public-demo-allocation.json', LOCAL_FIXTURE_URLS[1]],
    ['evidence.json', LOCAL_FIXTURE_URLS[2]],
  ];
  for (const [fileName, url] of fixtureRequests) {
    const { bytes } = await fetchResponseBytes(fetchImpl, url, fetchOptions, fileName);
    const expected = integrity.files[fileName];
    if (bytes.byteLength !== expected.bytes || await sha256(bytes, cryptoImpl) !== expected.sha256) {
      throw new TypeError(`packaged fixture integrity mismatch: ${fileName}`);
    }
    values[fileName] = decodeJson(bytes, fileName);
  }
  return deepFreeze({
    allocation: validateAllocationFixture(values['public-demo-allocation.json']),
    evidence: validateEvidenceFixture(values['evidence.json']),
  });
}

function invalid402(status) {
  return deepFreeze({
    live: false,
    status: Number.isInteger(status) ? status : null,
    offer: null,
    error: 'live endpoint did not return a valid 402 offer',
  });
}

export function validateLive402(status, body) {
  if (status !== 402 || !isRecord(body) || body.x402Version !== 1
      || !Array.isArray(body.accepts) || body.accepts.length === 0) {
    return invalid402(status);
  }
  const offer = body.accepts[0];
  const amount = offer?.maxAmountRequired;
  const payTo = offer?.payTo;
  const asset = offer?.asset;
  if (!isRecord(offer)
      || offer.scheme !== 'exact'
      || offer.network !== 'base-sepolia'
      || typeof amount !== 'string'
      || !ATOMIC_PATTERN.test(amount)
      || BigInt(amount) <= 0n
      || offer.resource !== LIVE_ENDPOINT
      || typeof payTo !== 'string'
      || !ADDRESS_PATTERN.test(payTo)
      || payTo.toLowerCase() !== EXPECTED_PAY_TO
      || typeof asset !== 'string'
      || !ADDRESS_PATTERN.test(asset)
      || asset.toLowerCase() !== EXPECTED_ASSET) {
    return invalid402(status);
  }
  return deepFreeze({
    live: true,
    status: 402,
    offer: {
      scheme: 'exact',
      network: 'base-sepolia',
      maxAmountRequired: amount,
      resource: LIVE_ENDPOINT,
      payTo,
      asset,
    },
    error: null,
  });
}

export function loadScenario(fixture, scenarioId = fixture?.defaultScenarioId) {
  validateAllocationFixture(fixture);
  if (typeof scenarioId !== 'string') throw new TypeError('scenario identifier must be a string');
  const scenario = fixture.scenarios.find((candidate) => candidate.id === scenarioId);
  if (!scenario) throw new TypeError(`unknown public demo scenario: ${scenarioId}`);
  return scenario;
}

function atomic(value, label) {
  if (typeof value !== 'string' || !ATOMIC_PATTERN.test(value)) {
    throw new TypeError(`invalid atomic amount: ${label}`);
  }
  return BigInt(value);
}

export function renderScenarioModel(fixture, scenarioId = fixture?.defaultScenarioId) {
  const scenario = loadScenario(fixture, scenarioId);
  const entries = scenario.allocation?.journalEntries;
  const displayAmounts = scenario.journalEntryDisplayUsdc;
  const expectedDebit = scenario.expectedGrossDebitAccountId;
  if (!Array.isArray(entries) || entries.length === 0
      || !Array.isArray(displayAmounts) || displayAmounts.length !== entries.length
      || typeof expectedDebit !== 'string' || !expectedDebit) {
    throw new TypeError('invalid kernel journal fixture');
  }
  let total = 0n;
  const rows = entries.map((entry, index) => {
    if (!hasExactKeys(entry, ['category', 'debitAccountId', 'creditAccountId', 'amountAtomic'])
        || entry.debitAccountId !== expectedDebit
        || typeof entry.creditAccountId !== 'string' || !entry.creditAccountId
        || typeof entry.category !== 'string' || !entry.category
        || typeof displayAmounts[index] !== 'string') {
      throw new TypeError('invalid kernel journal entry');
    }
    total += atomic(entry.amountAtomic, `journalEntries[${index}]`);
    return deepFreeze({
      category: entry.category,
      debitAccountId: entry.debitAccountId,
      creditAccountId: entry.creditAccountId,
      amountAtomic: entry.amountAtomic,
      amountUsdc: displayAmounts[index],
    });
  });
  if (total !== atomic(scenario.grossAtomic, 'grossAtomic')) {
    throw new TypeError('kernel journal does not conserve gross');
  }
  return deepFreeze({
    scenarioId: scenario.id,
    label: scenario.label,
    status: scenario.status,
    policy: scenario.policy,
    allocationKind: scenario.allocationKind,
    accountingLabel: scenario.accountingLabel,
    implementationNote: scenario.implementationNote,
    settlementNote: scenario.settlementNote,
    grossAtomic: scenario.grossAtomic,
    grossUsdc: scenario.grossUsdc,
    rows,
  });
}

function clear(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function textElement(documentObject, tagName, text, className) {
  const element = documentObject.createElement(tagName);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function renderAllocation(documentObject, output, model) {
  clear(output);
  output.append(
    textElement(documentObject, 'h3', model.label),
    textElement(documentObject, 'p', `Status: ${model.status} · Policy: ${model.policy}`, 'status-line'),
    textElement(documentObject, 'p', model.accountingLabel),
    textElement(documentObject, 'p', model.implementationNote),
    textElement(
      documentObject,
      'p',
      `Gross: ${model.grossAtomic} atomic units (${model.grossUsdc} testnet USDC)`,
      'mono',
    ),
  );
  const table = documentObject.createElement('table');
  const header = documentObject.createElement('tr');
  for (const label of ['category', 'debit account', 'credit account', 'atomic units', 'testnet USDC']) {
    header.append(textElement(documentObject, 'th', label));
  }
  table.append(header);
  for (const row of model.rows) {
    const tr = documentObject.createElement('tr');
    for (const value of [
      row.category,
      row.debitAccountId,
      row.creditAccountId,
      row.amountAtomic,
      row.amountUsdc,
    ]) {
      tr.append(textElement(documentObject, 'td', value));
    }
    table.append(tr);
  }
  output.append(table, textElement(documentObject, 'p', model.settlementNote, 'boundary'));
}

function renderEvidence(documentObject, output, evidence) {
  clear(output);
  const overhead = evidence.historicalOverhead;
  const transaction = evidence.historicalSkillLegTransactions[0];
  output.append(
    textElement(documentObject, 'h3', 'Evidence status'),
    textElement(
      documentObject,
      'p',
      `Suppressed route evidence: ${overhead.evidenceStatus}; publication allowed: ${overhead.publicationAllowed}.`,
    ),
    textElement(documentObject, 'p', overhead.publicText),
    textElement(documentObject, 'p', `Narrow historical transaction evidence: ${transaction.label}.`),
    textElement(documentObject, 'p', `Manifest record: ${transaction.manifestPath}`, 'mono'),
  );
  const list = documentObject.createElement('ul');
  for (const boundary of transaction.doesNotProve) {
    list.append(textElement(documentObject, 'li', `Does not prove: ${boundary}`));
  }
  output.append(list);
}

function renderLiveResult(documentObject, output, result) {
  clear(output);
  output.dataset.live = String(result.live);
  output.append(textElement(
    documentObject,
    'strong',
    result.live
      ? 'Valid live HTTP 402 offer from the fixed endpoint.'
      : 'Live endpoint did not return a valid 402 offer.',
  ));
  if (result.live) {
    output.append(textElement(
      documentObject,
      'p',
      `HTTP ${result.status}; ${result.offer.network}; ${result.offer.maxAmountRequired} atomic units.`,
      'mono',
    ));
  }
}

export async function fetchLiveOffer(
  fetchImpl,
  { deadlineMilliseconds = RESPONSE_DEADLINE_MILLISECONDS } = {},
) {
  try {
    const fetchOptions = {
      method: 'POST',
      redirect: 'error',
      cache: 'no-store',
      credentials: 'omit',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ input: 'help me tighten this prompt' }),
    };
    const { bytes, status } = await fetchResponseBytes(
      fetchImpl,
      LIVE_ENDPOINT,
      fetchOptions,
      'live endpoint',
      { requireOk: false, deadlineMilliseconds },
    );
    const body = decodeJson(bytes, 'live endpoint');
    return validateLive402(status, body);
  } catch {
    return invalid402(null);
  }
}

export async function mountDemo({
  document: documentObject,
  fetchImpl = fetch,
  cryptoImpl = crypto,
}) {
  if (!documentObject?.documentElement) throw new TypeError('document is required');
  const mountState = documentObject.documentElement.dataset.skillAssetMounted;
  if (mountState === 'true') return Object.freeze({ alreadyMounted: true });
  if (mountState === 'mounting') throw new Error('demo mount already in progress');
  documentObject.documentElement.dataset.skillAssetMounted = 'mounting';
  try {
    const fixtures = await loadPackagedFixtures({ fetchImpl, cryptoImpl });
    const select = documentObject.querySelector('#scenario-select');
    const allocationOutput = documentObject.querySelector('#allocation-output');
    const evidenceOutput = documentObject.querySelector('#evidence-output');
    const liveButton = documentObject.querySelector('#check-live-402');
    const liveOutput = documentObject.querySelector('#live-result');
    if (!select || !allocationOutput || !evidenceOutput || !liveButton || !liveOutput) {
      throw new Error('required demo controls are missing');
    }
    clear(select);
    for (const scenario of fixtures.allocation.scenarios) {
      const option = documentObject.createElement('option');
      option.value = scenario.id;
      option.textContent = `${scenario.label} [${scenario.status}]`;
      if (scenario.id === fixtures.allocation.defaultScenarioId) option.setAttribute('selected', '');
      select.append(option);
    }
    renderAllocation(
      documentObject,
      allocationOutput,
      renderScenarioModel(fixtures.allocation, fixtures.allocation.defaultScenarioId),
    );
    renderEvidence(documentObject, evidenceOutput, fixtures.evidence);
    select.addEventListener('change', () => {
      renderAllocation(
        documentObject,
        allocationOutput,
        renderScenarioModel(fixtures.allocation, select.value),
      );
    });
    liveButton.addEventListener('click', async () => {
      liveButton.disabled = true;
      try {
        renderLiveResult(documentObject, liveOutput, await fetchLiveOffer(fetchImpl));
      } finally {
        liveButton.disabled = false;
      }
    });
    documentObject.documentElement.dataset.skillAssetMounted = 'true';
    documentObject.documentElement.dataset.skillAssetMountCount = '1';
    return Object.freeze({ alreadyMounted: false });
  } catch (error) {
    delete documentObject.documentElement.dataset.skillAssetMounted;
    throw error;
  }
}

function renderFatalState(documentObject) {
  const fatal = documentObject.querySelector('#fatal-state');
  if (fatal) {
    fatal.hidden = false;
    fatal.textContent = 'Demo unavailable: packaged fixture validation failed.';
  }
}

function browserReady(documentObject) {
  if (documentObject.readyState !== 'loading') return Promise.resolve();
  return new Promise((resolve) => {
    documentObject.addEventListener('DOMContentLoaded', resolve, { once: true });
  });
}

const hasBrowser = typeof window !== 'undefined' && typeof document !== 'undefined';

export const browserBootstrapPromise = hasBrowser
  ? browserReady(document)
    .then(() => mountDemo({ document, fetchImpl: fetch, cryptoImpl: crypto }))
    .catch((error) => {
      renderFatalState(document);
      throw error;
    })
  : null;

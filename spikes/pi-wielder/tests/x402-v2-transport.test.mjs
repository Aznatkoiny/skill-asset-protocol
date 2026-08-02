import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
} from '@x402/core/http';

import {
  classifyX402PaymentResponse,
  createX402V2Transport,
  X402TransportError,
} from '../src/adapters/x402-v2-transport.mjs';
import {
  createResourceFetch,
  PAYMENT_HASH,
  PAYMENT_PAYLOAD,
  PAYMENT_REQUIRED,
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  SETTLEMENT,
} from './fixtures/x402-v2-resource.mjs';

const URL = PAYMENT_REQUIRED.resource.url;
const WALLET = PAYMENT_PAYLOAD.payload.authorization.from;
const DEFAULT_LIMITS = Object.freeze({
  requestTimeoutMs: 5_000,
  maximumResponseBytes: 1_048_576,
  maximumPaymentHeaderBytes: 16_384,
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function requestSnapshot(overrides = {}) {
  return {
    requestUrl: URL,
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'idempotency-key': 'wk_fixture_1',
    },
    bodyBytes: Buffer.from('{"prompt":"fixture"}'),
    ...overrides,
  };
}

function binding(overrides = {}) {
  return {
    network: PAYMENT_REQUIRED.accepts[0].network,
    walletAddress: WALLET,
    amountAtomic: PAYMENT_REQUIRED.accepts[0].amount,
    paymentHash: PAYMENT_HASH,
    ...overrides,
  };
}

function transport(fetchImpl, overrides = {}) {
  return createX402V2Transport({
    fetchImpl,
    mode: 'cdp-testnet',
    limits: DEFAULT_LIMITS,
    ...overrides,
  });
}

async function rejectsCode(operation, code) {
  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof X402TransportError);
    assert.equal(error.code, code);
    return true;
  });
}

function challengeResponse(paymentRequired = PAYMENT_REQUIRED, {
  body = Buffer.alloc(0),
  header = encodePaymentRequiredHeader(paymentRequired),
  headers,
} = {}) {
  return new Response(body, {
    status: 402,
    headers: headers ?? { 'PAYMENT-REQUIRED': header },
  });
}

function hangingBody(onCancel = () => {}) {
  return new ReadableStream({
    cancel(reason) { onCancel(reason); },
  }, { highWaterMark: 0 });
}

function responseFetch(responseOrFactory) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return typeof responseOrFactory === 'function'
        ? responseOrFactory(url, init, calls.length)
        : responseOrFactory;
    },
  };
}

test('constructor, mode, limits, request, and binding use closed schemas', async () => {
  for (const value of [
    null,
    {},
    { fetchImpl: async () => {}, mode: 'cdp-testnet', limits: DEFAULT_LIMITS, extra: true },
    { fetchImpl: new Proxy(async () => {}, {}), mode: 'cdp-testnet', limits: DEFAULT_LIMITS },
    { fetchImpl: async () => {}, mode: 'mainnet', limits: DEFAULT_LIMITS },
    { fetchImpl: async () => {}, mode: 'cdp-testnet', limits: { ...DEFAULT_LIMITS, extra: 1 } },
    { fetchImpl: async () => {}, mode: 'cdp-testnet', limits: { ...DEFAULT_LIMITS, requestTimeoutMs: 0 } },
    { fetchImpl: async () => {}, mode: 'cdp-testnet', limits: { ...DEFAULT_LIMITS, maximumResponseBytes: 1.5 } },
  ]) {
    assert.throws(() => createX402V2Transport(value), X402TransportError);
  }

  const recording = responseFetch(new Response(null, { status: 204 }));
  const client = transport(recording.fetchImpl);
  for (const request of [
    { ...requestSnapshot(), unknown: true },
    { ...requestSnapshot(), requestUrl: 'http://seller.example/paid/infer' },
    { ...requestSnapshot(), method: 'post' },
    { ...requestSnapshot(), bodyBytes: 'not bytes' },
    { ...requestSnapshot(), headers: { authorization: 'secret' } },
    { ...requestSnapshot(), headers: { cookie: 'session=secret' } },
    { ...requestSnapshot(), headers: { 'payment-signature': PAYMENT_SIGNATURE_HEADER } },
  ]) {
    await rejectsCode(() => client.probe(request), 'REQUEST_SCHEMA');
  }
  assert.equal(recording.calls.length, 0);

  const resource = createResourceFetch();
  const paidClient = transport(resource.fetchImpl);
  const request = requestSnapshot();
  await paidClient.probe(request);
  for (const invalid of [
    { ...binding(), extra: true },
    { ...binding(), network: '' },
    { ...binding(), network: 'eip155:84532 ' },
    { ...binding(), walletAddress: '0xnot-an-address' },
    { ...binding(), amountAtomic: '050000' },
    { ...binding(), amountAtomic: '9'.repeat(101) },
    { ...binding(), paymentHash: `sha256:${'A'.repeat(64)}` },
  ]) {
    await rejectsCode(() => paidClient.retryPaid({
      request,
      paymentHeader: PAYMENT_SIGNATURE_HEADER,
      binding: invalid,
    }), 'SETTLEMENT_BINDING');
  }
  assert.equal(resource.callCount(), 1);
});

test('mode admits only HTTPS in cdp-testnet and literal loopback HTTP in deterministic mode', async () => {
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(String(url));
    return new Response(null, { status: 204 });
  };
  const deterministic = createX402V2Transport({
    fetchImpl,
    mode: 'deterministic',
    limits: DEFAULT_LIMITS,
  });
  await deterministic.probe(requestSnapshot({ requestUrl: 'http://127.0.0.1:4402/paid' }));
  await deterministic.probe(requestSnapshot({ requestUrl: 'http://[::1]:4402/paid' }));
  await deterministic.probe(requestSnapshot());
  for (const requestUrl of [
    'http://localhost:4402/paid',
    'http://127.0.0.2:4402/paid',
    'http://user:pass@127.0.0.1:4402/paid',
    'http://127.0.0.1:4402/paid#fragment',
  ]) {
    await rejectsCode(
      () => deterministic.probe(requestSnapshot({ requestUrl })),
      'REQUEST_SCHEMA',
    );
  }
  assert.deepEqual(urls, [
    'http://127.0.0.1:4402/paid',
    'http://[::1]:4402/paid',
    URL,
  ]);
});

test('deterministic mode accepts a matching literal-loopback x402 challenge resource', async () => {
  const requestUrl = 'http://127.0.0.1:4402/paid';
  const paymentRequired = clone(PAYMENT_REQUIRED);
  paymentRequired.resource.url = requestUrl;
  const client = createX402V2Transport({
    fetchImpl: async () => challengeResponse(paymentRequired),
    mode: 'deterministic',
    limits: DEFAULT_LIMITS,
  });
  const result = await client.probe(requestSnapshot({ requestUrl }));
  assert.equal(result.kind, 'payment_required');
  assert.equal(result.paymentRequired.resource.url, requestUrl);
});

test('a later approval flow may freshly probe the same ordinary request snapshot', async () => {
  let calls = 0;
  const client = transport(async () => {
    calls += 1;
    return challengeResponse();
  });
  const request = requestSnapshot();
  assert.equal((await client.probe(request)).kind, 'payment_required');
  assert.equal((await client.probe(request)).kind, 'payment_required');
  assert.equal(calls, 2);
});

test('official codecs, one cloned body, and exactly one unpaid plus one paid call interoperate', async () => {
  const resource = createResourceFetch();
  const client = transport(resource.fetchImpl);
  const body = Buffer.from('{"prompt":"immutable"}');
  const request = requestSnapshot({ bodyBytes: body });

  const challenge = await client.probe(request);
  assert.equal(challenge.kind, 'payment_required');
  assert.deepEqual(challenge.paymentRequired, PAYMENT_REQUIRED);
  assert.ok(Object.isFrozen(challenge));
  assert.ok(Object.isFrozen(challenge.paymentRequired));
  assert.equal(client.encodePayment(PAYMENT_PAYLOAD), PAYMENT_SIGNATURE_HEADER);
  const paymentHash = `sha256:${crypto.createHash('sha256')
    .update(Buffer.from(PAYMENT_SIGNATURE_HEADER, 'ascii')).digest('hex')}`;
  assert.equal(paymentHash, PAYMENT_HASH);

  body.fill(0x78);
  request.bodyBytes = Buffer.from('caller replacement');
  const paid = await client.retryPaid({
    request,
    paymentHeader: PAYMENT_SIGNATURE_HEADER,
    binding: binding({ paymentHash }),
  });
  assert.equal(paid.kind, 'settled_response');
  assert.deepEqual(paid.settlement, SETTLEMENT);
  assert.equal(paid.status, 200);
  assert.equal(paid.executionState, 'succeeded');
  assert.deepEqual(paid.body, Buffer.from('{"ok":true}'));
  assert.equal(resource.callCount(), 2);

  const [unpaid, paidCall] = resource.calls;
  assert.equal(unpaid.redirect, 'manual');
  assert.equal(paidCall.redirect, 'manual');
  assert.equal(unpaid.credentials, 'omit');
  assert.equal(paidCall.credentials, 'omit');
  assert.equal(unpaid.headers['payment-signature'], undefined);
  assert.equal(paidCall.headers['payment-signature'], PAYMENT_SIGNATURE_HEADER);
  const withoutPayment = { ...paidCall.headers };
  delete withoutPayment['payment-signature'];
  assert.deepEqual(withoutPayment, unpaid.headers);
  assert.equal(unpaid.url, paidCall.url);
  assert.equal(unpaid.method, paidCall.method);
  assert.deepEqual(unpaid.bodyBytes, Buffer.from('{"prompt":"immutable"}'));
  assert.deepEqual(paidCall.bodyBytes, unpaid.bodyBytes);

  await rejectsCode(() => client.retryPaid({
    request,
    paymentHeader: PAYMENT_SIGNATURE_HEADER,
    binding: binding(),
  }), 'REQUEST_ALREADY_RETRIED');
  assert.equal(resource.callCount(), 2);
});

test('encodePayment uses the official codec and enforces the signature header byte ceiling', () => {
  const client = createX402V2Transport({
    fetchImpl: async () => new Response(null, { status: 204 }),
    mode: 'cdp-testnet',
    limits: { ...DEFAULT_LIMITS, maximumPaymentHeaderBytes: 64 },
  });
  assert.throws(() => client.encodePayment(PAYMENT_PAYLOAD), (error) => (
    error instanceof X402TransportError && error.code === 'PAYMENT_SIGNATURE_TOO_LARGE'
  ));
  assert.throws(() => client.encodePayment({ ...PAYMENT_PAYLOAD, extra: () => {} }), (error) => (
    error instanceof X402TransportError && error.code === 'PAYMENT_PAYLOAD_SCHEMA'
  ));
});

test('probe returns bounded ordinary responses and never follows redirects', async () => {
  const ordinary = responseFetch(new Response('ordinary', { status: 201 }));
  const result = await transport(ordinary.fetchImpl).probe(requestSnapshot());
  assert.deepEqual(result, {
    kind: 'response',
    status: 201,
    body: Buffer.from('ordinary'),
  });
  assert.equal(ordinary.calls.length, 1);
  assert.equal(ordinary.calls[0].init.redirect, 'manual');

  const redirected = responseFetch(new Response(null, {
    status: 302,
    headers: { location: 'https://other.example/steal' },
  }));
  await rejectsCode(
    () => transport(redirected.fetchImpl).probe(requestSnapshot()),
    'REDIRECT_FORBIDDEN',
  );
  assert.equal(redirected.calls.length, 1);
});

test('probe rejects missing, duplicate, malformed, oversized, or non-v2 challenge headers', async () => {
  const duplicateHeaders = new Headers([
    ['PAYMENT-REQUIRED', PAYMENT_REQUIRED_HEADER],
    ['PAYMENT-REQUIRED', PAYMENT_REQUIRED_HEADER],
  ]);
  const cases = [
    ['missing', new Response(null, { status: 402 }), 'PAYMENT_REQUIRED_MISSING'],
    ['legacy header only', new Response(null, {
      status: 402,
      headers: { 'X-PAYMENT-REQUIRED': PAYMENT_REQUIRED_HEADER },
    }), 'PAYMENT_REQUIRED_MISSING'],
    ['duplicate', challengeResponse(PAYMENT_REQUIRED, { headers: duplicateHeaders }), 'PAYMENT_REQUIRED_DUPLICATE'],
    ['malformed base64', challengeResponse(PAYMENT_REQUIRED, { header: '***' }), 'PAYMENT_REQUIRED_MALFORMED'],
    ['malformed JSON', challengeResponse(PAYMENT_REQUIRED, {
      header: Buffer.from('{bad json', 'utf8').toString('base64'),
    }), 'PAYMENT_REQUIRED_MALFORMED'],
    ['over ceiling', challengeResponse(PAYMENT_REQUIRED, { header: 'A'.repeat(16_385) }), 'PAYMENT_REQUIRED_TOO_LARGE'],
    ['v1', challengeResponse({ ...PAYMENT_REQUIRED, x402Version: 1 }), 'PAYMENT_REQUIRED_SCHEMA'],
  ];
  for (const [name, response, code] of cases) {
    const recording = responseFetch(response);
    await rejectsCode(
      () => transport(recording.fetchImpl).probe(requestSnapshot()),
      code,
    );
    assert.equal(recording.calls.length, 1, name);
  }
});

test('probe applies closed structural validation without selecting or filtering candidates', async () => {
  const malformed = [];
  const add = (name, mutate) => {
    const value = clone(PAYMENT_REQUIRED);
    mutate(value);
    malformed.push([name, value]);
  };
  add('unknown top-level key', (value) => { value.unknown = true; });
  add('missing resource', (value) => { delete value.resource; });
  add('unknown resource key', (value) => { value.resource.serviceName = 'nope'; });
  add('empty description', (value) => { value.resource.description = ''; });
  add('malformed MIME type', (value) => { value.resource.mimeType = 'not a MIME type'; });
  add('empty accepts', (value) => { value.accepts = []; });
  add('missing requirement key', (value) => { delete value.accepts[0].payTo; });
  add('unknown requirement key', (value) => { value.accepts[0].price = '50000'; });
  add('empty scheme', (value) => { value.accepts[0].scheme = ''; });
  add('noncanonical scheme', (value) => { value.accepts[0].scheme = 'exact scheme'; });
  add('noncanonical network', (value) => { value.accepts[0].network = 'eip155 84532'; });
  add('invalid amount', (value) => { value.accepts[0].amount = '050000'; });
  add('invalid timeout', (value) => { value.accepts[0].maxTimeoutSeconds = 0; });
  add('non-object extra', (value) => { value.accepts[0].extra = []; });
  for (const [name, value] of malformed) {
    const recording = responseFetch(challengeResponse(value));
    await rejectsCode(
      () => transport(recording.fetchImpl).probe(requestSnapshot()),
      'PAYMENT_REQUIRED_SCHEMA',
    );
    assert.equal(recording.calls.length, 1, name);
  }

  const options = clone(PAYMENT_REQUIRED);
  options.accepts.push({
    scheme: 'different-scheme',
    network: 'different:network',
    asset: 'different-asset',
    amount: '90000',
    payTo: 'different-payee',
    maxTimeoutSeconds: 30,
    extra: { vendor: 'unselected' },
  });
  const client = transport(async () => challengeResponse(options));
  const result = await client.probe(requestSnapshot());
  assert.deepEqual(result.paymentRequired.accepts, options.accepts);
  assert.equal(result.paymentRequired.accepts.length, 2);
});

test('probe rejects a mismatched resource URL and an oversized 402 body', async () => {
  const mismatched = clone(PAYMENT_REQUIRED);
  mismatched.resource.url = 'https://seller.example/paid/other';
  await rejectsCode(
    () => transport(async () => challengeResponse(mismatched)).probe(requestSnapshot()),
    'RESOURCE_URL_MISMATCH',
  );

  const client = createX402V2Transport({
    fetchImpl: async () => challengeResponse(PAYMENT_REQUIRED, { body: Buffer.alloc(65) }),
    mode: 'cdp-testnet',
    limits: { ...DEFAULT_LIMITS, maximumResponseBytes: 64 },
  });
  await rejectsCode(() => client.probe(requestSnapshot()), 'RESPONSE_TOO_LARGE');
});

test('retryPaid validates exact persisted header/hash and requires the probed request identity', async () => {
  const resource = createResourceFetch();
  const client = transport(resource.fetchImpl);
  const request = requestSnapshot();
  await client.probe(request);
  await rejectsCode(() => client.retryPaid({
    request: requestSnapshot(),
    paymentHeader: PAYMENT_SIGNATURE_HEADER,
    binding: binding(),
  }), 'REQUEST_NOT_PROBED');
  await rejectsCode(() => client.retryPaid({
    request,
    paymentHeader: `${PAYMENT_SIGNATURE_HEADER[0] === 'A' ? 'B' : 'A'}${PAYMENT_SIGNATURE_HEADER.slice(1)}`,
    binding: binding(),
  }), 'PAYMENT_HASH_MISMATCH');
  await rejectsCode(() => client.retryPaid({
    request,
    paymentHeader: PAYMENT_SIGNATURE_HEADER,
    binding: binding({ paymentHash: `sha256:${'f'.repeat(64)}` }),
  }), 'PAYMENT_HASH_MISMATCH');
  assert.equal(resource.callCount(), 1);
});

test('oversized paid header is rejected before Base64 allocation, fetch, or state mutation', async () => {
  const resource = createResourceFetch();
  let fetchCalls = 0;
  let paidFetchCalls = 0;
  const client = transport(async (...arguments_) => {
    fetchCalls += 1;
    if (fetchCalls > 1) paidFetchCalls += 1;
    return await resource.fetchImpl(...arguments_);
  });
  const request = requestSnapshot();
  await client.probe(request);

  const oversized = 'A'.repeat(DEFAULT_LIMITS.maximumPaymentHeaderBytes + 1);
  const originalFrom = Buffer.from;
  let base64DecodeCalls = 0;
  Buffer.from = function instrumentedBufferFrom(value, encoding, ...rest) {
    if (encoding === 'base64') {
      base64DecodeCalls += 1;
      throw new Error('unsafe Base64 allocation reached');
    }
    return Reflect.apply(originalFrom, Buffer, [value, encoding, ...rest]);
  };
  try {
    await rejectsCode(() => client.retryPaid({
      request,
      paymentHeader: oversized,
      binding: binding(),
    }), 'PAYMENT_HEADER_SCHEMA');
  } finally {
    Buffer.from = originalFrom;
  }
  assert.equal(base64DecodeCalls, 0);
  assert.equal(paidFetchCalls, 0);

  const paid = await client.retryPaid({
    request,
    paymentHeader: PAYMENT_SIGNATURE_HEADER,
    binding: binding(),
  });
  assert.equal(paid.kind, 'settled_response');
  assert.equal(paidFetchCalls, 1);
});

test('classifier returns only frozen Task5-compatible settlement evidence', () => {
  const responseWithIgnoredMetadata = {
    ...PAYMENT_RESPONSE,
    extensions: { trace: 'RAW_EXTENSION_SENTINEL' },
    extra: { facilitatorLatencyMs: 1 },
  };
  const classified = classifyX402PaymentResponse({
    rawHeader: encodePaymentResponseHeader(responseWithIgnoredMetadata),
    decoded: responseWithIgnoredMetadata,
    binding: binding(),
  });
  assert.equal(classified.kind, 'settled');
  assert.deepEqual({
    ...classified.settlement,
    headerHash: SETTLEMENT.headerHash,
  }, SETTLEMENT);
  assert.ok(Object.isFrozen(classified));
  assert.ok(Object.isFrozen(classified.settlement));
  assert.deepEqual(Object.keys(classified.settlement).sort(), [
    'amountAtomic',
    'headerHash',
    'network',
    'payer',
    'paymentHash',
    'source',
    'success',
    'transaction',
  ]);
  assert.equal(JSON.stringify(classified).includes(PAYMENT_RESPONSE_HEADER), false);
  assert.equal(JSON.stringify(classified).includes('errorMessage'), false);
  assert.equal(JSON.stringify(classified).includes('extensions'), false);
  assert.equal(JSON.stringify(classified).includes('extra'), false);
  assert.equal(JSON.stringify(classified).includes('RAW_EXTENSION_SENTINEL'), false);
});

test('classifier allows exact success with absent amount but requires payer', () => {
  const absentAmount = { ...PAYMENT_RESPONSE };
  delete absentAmount.amount;
  const rawHeader = encodePaymentResponseHeader(absentAmount);
  const result = classifyX402PaymentResponse({
    rawHeader,
    decoded: absentAmount,
    binding: binding(),
  });
  assert.equal(result.kind, 'settled');
  assert.equal(Object.hasOwn(result.settlement, 'amountAtomic'), false);

  const absentPayer = { ...PAYMENT_RESPONSE };
  delete absentPayer.payer;
  const missing = classifyX402PaymentResponse({
    rawHeader: encodePaymentResponseHeader(absentPayer),
    decoded: absentPayer,
    binding: binding(),
  });
  assert.deepEqual(missing, { kind: 'unresolved', reasonCode: 'SETTLEMENT_PAYER_MISSING' });
});

test('classifier fails closed for every recognized-field mutation and never trusts seller text', () => {
  const mutations = [
    ['success false empty transaction', (value) => { value.success = false; value.transaction = ''; }, 'SETTLEMENT_REPORTED_FAILURE'],
    ['success false reverted transaction', (value) => { value.success = false; value.transaction = `0x${'0'.repeat(64)}`; }, 'SETTLEMENT_REPORTED_FAILURE'],
    ['success type', (value) => { value.success = 1; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['transaction missing', (value) => { delete value.transaction; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['transaction type', (value) => { value.transaction = 1; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['transaction malformed', (value) => { value.transaction = '0x1234'; }, 'SETTLEMENT_TRANSACTION_INVALID'],
    ['network missing', (value) => { delete value.network; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['network type', (value) => { value.network = 1; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['network mismatch', (value) => { value.network = 'eip155:8453'; }, 'SETTLEMENT_NETWORK_MISMATCH'],
    ['payer type', (value) => { value.payer = 1; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['payer malformed', (value) => { value.payer = 'payer'; }, 'SETTLEMENT_PAYER_INVALID'],
    ['payer mismatch', (value) => { value.payer = `0x${'2'.repeat(40)}`; }, 'SETTLEMENT_PAYER_MISMATCH'],
    ['amount type', (value) => { value.amount = 50_000; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['amount noncanonical', (value) => { value.amount = '050000'; }, 'SETTLEMENT_AMOUNT_INVALID'],
    ['amount mismatch', (value) => { value.amount = '50001'; }, 'SETTLEMENT_AMOUNT_MISMATCH'],
    ['errorReason type', (value) => { value.errorReason = 1; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['errorReason on success', (value) => { value.errorReason = 'seller-controlled'; }, 'SETTLEMENT_SUCCESS_HAS_ERROR'],
    ['errorMessage type', (value) => { value.errorMessage = 1; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['errorMessage on success', (value) => { value.errorMessage = 'RAW_SELLER_SENTINEL'; }, 'SETTLEMENT_SUCCESS_HAS_ERROR'],
    ['extensions type', (value) => { value.extensions = []; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['extra type', (value) => { value.extra = []; }, 'SETTLEMENT_SCHEMA_INVALID'],
    ['unknown key', (value) => { value.authorizationId = 'invented'; }, 'SETTLEMENT_SCHEMA_INVALID'],
  ];
  for (const [name, mutate, reasonCode] of mutations) {
    const decoded = clone(PAYMENT_RESPONSE);
    mutate(decoded);
    const result = classifyX402PaymentResponse({
      rawHeader: encodePaymentResponseHeader(decoded),
      decoded,
      binding: binding(),
    });
    assert.deepEqual(result, { kind: 'unresolved', reasonCode }, name);
    assert.equal(JSON.stringify(result).includes('RAW_SELLER_SENTINEL'), false, name);
  }
});

test('classifier binds decoded bytes and the exact ASCII payment hash', () => {
  const substituted = { ...PAYMENT_RESPONSE, amount: '50001' };
  assert.deepEqual(classifyX402PaymentResponse({
    rawHeader: PAYMENT_RESPONSE_HEADER,
    decoded: substituted,
    binding: binding(),
  }), { kind: 'unresolved', reasonCode: 'SETTLEMENT_DECODE_MISMATCH' });
  assert.deepEqual(classifyX402PaymentResponse({
    rawHeader: '***',
    decoded: PAYMENT_RESPONSE,
    binding: binding(),
  }), { kind: 'unresolved', reasonCode: 'SETTLEMENT_HEADER_INVALID' });
  assert.deepEqual(classifyX402PaymentResponse({
    rawHeader: PAYMENT_RESPONSE_HEADER,
    decoded: PAYMENT_RESPONSE,
    binding: binding({ paymentHash: `sha256:${'F'.repeat(64)}` }),
  }), { kind: 'unresolved', reasonCode: 'SETTLEMENT_BINDING_INVALID' });
});

test('loss or timeout before trustworthy paid response headers is ambiguous and makes no third call', async () => {
  for (const [name, second, expected] of [
    ['connection loss', async () => { throw new Error('ECONNRESET'); }, 'PAID_FETCH_FAILED'],
    ['timeout', async () => await new Promise(() => {}), 'PAID_RESPONSE_TIMEOUT'],
  ]) {
    let calls = 0;
    const client = createX402V2Transport({
      fetchImpl: async (...args) => {
        calls += 1;
        if (calls === 1) return challengeResponse();
        return await second(...args);
      },
      mode: 'cdp-testnet',
      limits: { ...DEFAULT_LIMITS, requestTimeoutMs: 25 },
    });
    const request = requestSnapshot();
    await client.probe(request);
    const result = await client.retryPaid({
      request,
      paymentHeader: PAYMENT_SIGNATURE_HEADER,
      binding: binding(),
    });
    assert.deepEqual(result, { kind: 'paid_response_ambiguous', reasonCode: expected }, name);
    assert.equal(calls, 2, name);
  }
});

test('second 402, changed challenge, or absent settlement always retains the hold', async () => {
  const changed = clone(PAYMENT_REQUIRED);
  changed.accepts[0].amount = '50001';
  for (const [name, paidResponse, reasonCode] of [
    ['second 402', challengeResponse(), 'SECOND_PAYMENT_REQUIRED'],
    ['changed second 402', challengeResponse(changed), 'SECOND_PAYMENT_REQUIRED'],
    ['missing settlement', new Response('paid?', { status: 200 }), 'PAYMENT_RESPONSE_MISSING'],
  ]) {
    let calls = 0;
    const client = transport(async () => {
      calls += 1;
      return calls === 1 ? challengeResponse() : paidResponse;
    });
    const request = requestSnapshot();
    await client.probe(request);
    assert.deepEqual(await client.retryPaid({
      request,
      paymentHeader: PAYMENT_SIGNATURE_HEADER,
      binding: binding(),
    }), { kind: 'paid_response_ambiguous', reasonCode }, name);
    assert.equal(calls, 2, name);
  }
});

test('missing, duplicate, malformed, oversized, or mismatched settlement is ambiguous for every status', async () => {
  const duplicate = new Headers([
    ['PAYMENT-RESPONSE', PAYMENT_RESPONSE_HEADER],
    ['PAYMENT-RESPONSE', PAYMENT_RESPONSE_HEADER],
  ]);
  const malformedCases = [
    ['legacy header only', {
      'X-PAYMENT-RESPONSE': PAYMENT_RESPONSE_HEADER,
    }, 'PAYMENT_RESPONSE_MISSING'],
    ['duplicate', duplicate, 'PAYMENT_RESPONSE_DUPLICATE'],
    ['malformed base64', { 'PAYMENT-RESPONSE': '***' }, 'PAYMENT_RESPONSE_MALFORMED'],
    ['malformed json', {
      'PAYMENT-RESPONSE': Buffer.from('{bad json').toString('base64'),
    }, 'PAYMENT_RESPONSE_MALFORMED'],
    ['oversized', { 'PAYMENT-RESPONSE': 'A'.repeat(16_385) }, 'PAYMENT_RESPONSE_TOO_LARGE'],
    ['success false', {
      'PAYMENT-RESPONSE': encodePaymentResponseHeader({
        ...PAYMENT_RESPONSE,
        success: false,
        errorReason: 'rejected',
      }),
    }, 'SETTLEMENT_REPORTED_FAILURE'],
  ];
  for (const status of [200, 302, 404, 500]) {
    for (const [name, headers, reasonCode] of malformedCases) {
      let calls = 0;
      const client = transport(async () => {
        calls += 1;
        return calls === 1
          ? challengeResponse()
          : new Response('untrusted body', { status, headers });
      });
      const request = requestSnapshot();
      await client.probe(request);
      assert.deepEqual(await client.retryPaid({
        request,
        paymentHeader: PAYMENT_SIGNATURE_HEADER,
        binding: binding(),
      }), { kind: 'paid_response_ambiguous', reasonCode }, `${status} ${name}`);
      assert.equal(calls, 2, `${status} ${name}`);
    }
  }
});

test('a valid settlement commits payment while 2xx timeout, overflow, or disconnect is execution unknown', async () => {
  const cases = [
    ['timeout', () => hangingBody(), 'BODY_TIMEOUT'],
    ['overflow', () => Buffer.alloc(65), 'BODY_TOO_LARGE'],
    ['disconnect', () => new ReadableStream({
      pull(controller) { controller.error(new Error('disconnect')); },
    }), 'BODY_READ_FAILED'],
  ];
  for (const [name, makeBody, deliveryReason] of cases) {
    let calls = 0;
    const client = createX402V2Transport({
      fetchImpl: async () => {
        calls += 1;
        return calls === 1
          ? challengeResponse()
          : new Response(makeBody(), {
            status: 200,
            headers: { 'PAYMENT-RESPONSE': PAYMENT_RESPONSE_HEADER },
          });
      },
      mode: 'cdp-testnet',
      limits: {
        requestTimeoutMs: 25,
        maximumResponseBytes: 64,
        maximumPaymentHeaderBytes: 16_384,
      },
    });
    const request = requestSnapshot();
    await client.probe(request);
    assert.deepEqual(await client.retryPaid({
      request,
      paymentHeader: PAYMENT_SIGNATURE_HEADER,
      binding: binding(),
    }), {
      kind: 'settled_response',
      settlement: SETTLEMENT,
      status: 200,
      body: null,
      executionState: 'unknown',
      deliveryReason,
    }, name);
    assert.equal(calls, 2, name);
  }
});

test('validly settled 3xx, 4xx, and 5xx are execution failed immediately with no follow or third call', async () => {
  for (const status of [302, 404, 500]) {
    let calls = 0;
    let bodyCancelled = false;
    const client = transport(async () => {
      calls += 1;
      return calls === 1
        ? challengeResponse()
        : new Response(hangingBody(() => { bodyCancelled = true; }), {
          status,
          headers: {
            'PAYMENT-RESPONSE': PAYMENT_RESPONSE_HEADER,
            location: 'https://other.example/never-followed',
          },
        });
    });
    const request = requestSnapshot();
    await client.probe(request);
    assert.deepEqual(await client.retryPaid({
      request,
      paymentHeader: PAYMENT_SIGNATURE_HEADER,
      binding: binding(),
    }), {
      kind: 'settled_response',
      settlement: SETTLEMENT,
      status,
      body: null,
      executionState: 'failed',
      deliveryReason: 'HTTP_STATUS_FAILURE',
    });
    assert.equal(calls, 2);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(bodyCancelled, true);
  }
});

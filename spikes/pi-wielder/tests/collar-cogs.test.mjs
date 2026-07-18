import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createAnthropicExecutor,
  createCollar,
  DEFAULT_PROVIDER_RESPONSE_BYTES,
  DEFAULT_PROVIDER_TIMEOUT_MS,
  SKILL_ID,
} from '../src/collar.mjs';
import {
  catalogDigest,
  EXECUTION_CATALOG,
} from '../src/execution-economics.mjs';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import {
  createInvocationJournal,
  createReceiptSigner,
  verifySignedReceipt,
} from '../src/invocation-journal.mjs';
import {
  createProxy,
  payingFetch,
} from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { createMockFacilitatorTransport } from '../src/x402-seller.mjs';
import { paymentPolicyFor } from './payment-policy-fixture.mjs';

const PAY_TO = '0x000000000000000000000000000000000000dead';

function stack(collarOptions = {}) {
  const facilitator = createMockFacilitator();
  const transport = createMockFacilitatorTransport(
    (url, init) => facilitator.request(url, init),
  );
  const collar = createCollar({ facilitatorTransport: transport, ...collarOptions });
  const proxy = createProxy({
    account: throwawayAccount(),
    collarUrl: 'http://collar.test',
    collarFetch: (url, init) => collar.app.request(url, init),
    gatewayFetch: async () => { throw new Error('model gateway must not run'); },
    trustedCollarPublicKeyPem: collar.journal.signingPublicKeyPem,
    trustedCollarKeyId: collar.journal.signingKeyId,
  });
  return { facilitator, collar, proxy };
}

async function invoke(proxy, execution = undefined) {
  const body = execution === undefined
    ? { input: 'optimize this prompt' }
    : { input: 'optimize this prompt', execution };
  const res = await proxy.app.request(`http://proxy.test/invoke/${SKILL_ID}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { res, body: await res.json() };
}

async function settlementCrash({ executionCatalog = EXECUTION_CATALOG, executeSkill }) {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  let providerCalls = 0;
  const countedExecuteSkill = async (...args) => {
    providerCalls += 1;
    return executeSkill(...args);
  };
  const transport = createMockFacilitatorTransport((url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  const journal = createInvocationJournal({ signer: createReceiptSigner() });
  const beforeRestart = createCollar({
    facilitatorTransport: transport,
    journal,
    lifecycleFaults: {
      afterSettlementRecorded: async () => { throw new Error('injected crash after authoritative settlement'); },
    },
    executeSkill: countedExecuteSkill,
  });
  const account = throwawayAccount();
  const sellerUrl = `http://seller.test/invoke/${SKILL_ID}`;
  const idempotencyKey = `settlement-crash-${crypto.randomUUID()}`;
  const requestBody = JSON.stringify({ input: 'same frozen request' });
  const paymentPolicy = paymentPolicyFor(sellerUrl, PAY_TO);
  await assert.rejects(() => payingFetch(account, sellerUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: requestBody,
  }, {
    idempotencyKey,
    paymentPolicy,
    fetchImpl: (url, init) => beforeRestart.app.request(url, init),
  }), (error) => error.code === 'SETTLEMENT_EVIDENCE');
  const persistedPayment = paymentPolicy.recoverSignedAuthorization({
    authorizationId: idempotencyKey,
    requestUrl: sellerUrl,
    method: 'POST',
    bodyBytes: requestBody,
  });
  const crashedRecord = journal.getByIdempotencyKey(idempotencyKey);
  assert.equal(crashedRecord.payment.state, 'settled');
  assert.equal(crashedRecord.execution.state, 'authorized');
  assert.equal(crashedRecord.accounting, null);
  assert.equal(crashedRecord.receipt, null);

  const afterRestart = createCollar({
    facilitatorTransport: transport,
    journal,
    executionCatalog,
    executeSkill: countedExecuteSkill,
  });
  const retry = (xPayment = persistedPayment.xPayment) => afterRestart.app.request(sellerUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'X-PAYMENT': xPayment,
    },
    body: requestBody,
  });
  return {
    afterRestart,
    facilitatorCallCount: () => facilitatorCalls,
    journal,
    providerCallCount: () => providerCalls,
    retry,
    xPayment: persistedPayment.xPayment,
  };
}

test('known provider usage is charged before the Royalty pool and binds exact output bytes', async () => {
  const services = stack();
  const { res, body } = await invoke(services.proxy);
  assert.equal(res.status, 200);
  assert.equal(typeof body.output, 'string');
  const receipt = body.receipt.receipt;
  const accounting = receipt.accounting;
  assert.equal(receipt.schemaVersion, 2);
  assert.equal(accounting.schemaVersion, 2);
  assert.equal(accounting.executionCogs.status, 'known');
  assert.equal(accounting.executionCogs.actualAtomic, '756');
  assert.equal(accounting.executionCostAtomic, '756');
  assert.equal(accounting.settlementCostAtomic, '1000');
  assert.equal(accounting.royaltyPoolAtomic, '236994');
  assert.equal(accounting.protocolFeeAtomic, '6250');
  assert.equal(accounting.refundReserveAtomic, '5000');
  assert.equal(accounting.contributionMarginAtomic, '6250');
  assert.equal(receipt.quote.executionQuote.quoteId, accounting.quoteId);
  assert.equal(receipt.execution.outcomeHash, `sha256:${crypto.createHash('sha256').update(body.output).digest('hex')}`);
  assert.equal(
    BigInt(accounting.executionCostAtomic)
      + BigInt(accounting.settlementCostAtomic)
      + BigInt(accounting.protocolFeeAtomic)
      + BigInt(accounting.royaltyPoolAtomic)
      + BigInt(accounting.refundReserveAtomic),
    250_000n,
  );
  assert.equal(
    accounting.journalEntries.reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n),
    250_000n,
  );
});

test('missing usage fails settled execution, emits no output, and holds the full gross', async () => {
  const services = stack({
    executeSkill: async () => ({ output: 'safe output', usage: null }),
  });
  const { res, body } = await invoke(services.proxy);
  assert.equal(res.status, 500);
  assert.equal(body.output, undefined);
  assert.equal(body.receipt.receipt.execution.failureClass, 'COGS_UNKNOWN');
  const accounting = body.receipt.receipt.accounting;
  assert.equal(accounting.executionCogs.status, 'unknown');
  assert.equal(accounting.executionCogs.actualAtomic, null);
  assert.equal(accounting.executionCogs.chargedAtomic, null);
  assert.equal(accounting.executionCogs.quotedWorstCaseAtomic, '79872');
  assert.equal(accounting.royaltyPoolAtomic, '0');
  assert.deepEqual(accounting.holderCredits, []);
  assert.deepEqual(accounting.ancestorCredits, []);
  assert.equal(accounting.journalEntries[0].amountAtomic, accounting.grossAtomic);
});

test('synthetic pricing blocks live adapter construction even when live mode is requested', () => {
  let constructions = 0;
  assert.throws(() => createCollar({
    facilitatorTransport: createMockFacilitatorTransport(async () => { throw new Error('must not fetch'); }),
    mockLlm: false,
    allowLiveProvider: true,
    liveExecutorFactory: () => { constructions += 1; return async () => ({ output: '', usage: null }); },
  }), (error) => error.code === 'LIVE_CATALOG_EVIDENCE');
  assert.equal(constructions, 0);
});

test('Collar live-provider gate accepts only the exact boolean true', () => {
  let constructions = 0;
  for (const allowLiveProvider of [false, 1, 'true', {}, []]) {
    assert.throws(() => createCollar({
      facilitatorTransport: createMockFacilitatorTransport(async () => {
        throw new Error('must not fetch');
      }),
      mockLlm: false,
      allowLiveProvider,
      liveExecutorFactory: () => {
        constructions += 1;
        return async () => ({ output: '', usage: null });
      },
    }), (error) => error.code === 'LIVE_PRICING_UNAPPROVED');
  }
  assert.equal(constructions, 0);
});

test('live approval is rechecked against canonical catalog bytes before adapter construction', () => {
  const catalog = structuredClone(EXECUTION_CATALOG);
  Object.assign(catalog, {
    evidenceLabel: 'human_verified',
    source: 'https://provider.example/pricing/2026-07-17',
    asOf: '2026-07-17T00:00:00.000Z',
  });
  const liveApproval = { catalogDigest: catalogDigest(catalog), spendCapAtomic: '250000' };
  catalog.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '15000001';
  let constructions = 0;
  assert.throws(() => createCollar({
    facilitatorTransport: createMockFacilitatorTransport(async () => { throw new Error('must not fetch'); }),
    mockLlm: false,
    allowLiveProvider: true,
    executionCatalog: catalog,
    liveApproval,
    liveExecutorFactory: () => { constructions += 1; return async () => {}; },
  }), (error) => error.code === 'LIVE_CATALOG_DIGEST');
  assert.equal(constructions, 0);
});

test('Collar refuses live provider execution behind mock x402 settlement', () => {
  const catalog = structuredClone(EXECUTION_CATALOG);
  Object.assign(catalog, {
    evidenceLabel: 'human_verified',
    source: 'https://provider.example/pricing/2026-07-18',
    asOf: '2026-07-18T00:00:00.000Z',
  });
  const liveApproval = {
    catalogDigest: catalogDigest(catalog),
    spendCapAtomic: '250000',
  };
  let constructions = 0;
  assert.throws(() => createCollar({
    facilitatorTransport: createMockFacilitatorTransport(async () => {
      throw new Error('mock facilitator must not run');
    }),
    mockLlm: false,
    allowLiveProvider: true,
    executionCatalog: catalog,
    liveApproval,
    liveExecutorFactory: () => {
      constructions += 1;
      return async () => ({ output: '', usage: null });
    },
  }), /live provider execution requires live x402 settlement/i);
  assert.equal(constructions, 0);
});

test('a restarted Collar rejects pre-settlement quote drift before facilitator or payment.signed', async () => {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  let providerCalls = 0;
  const transport = createMockFacilitatorTransport((url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  const journal = createInvocationJournal({ signer: createReceiptSigner() });
  const beforeRestart = createCollar({ facilitatorTransport: transport, journal });
  const changedCatalog = structuredClone(EXECUTION_CATALOG);
  changedCatalog.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '15000001';
  const afterRestart = createCollar({
    facilitatorTransport: transport,
    journal,
    executionCatalog: changedCatalog,
    executeSkill: async () => { providerCalls += 1; return { output: 'must not run', usage: null }; },
  });
  let sellerRequests = 0;
  const sellerUrl = `http://seller.test/invoke/${SKILL_ID}`;
  await assert.rejects(() => payingFetch(throwawayAccount(), sellerUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'same frozen request' }),
  }, {
    idempotencyKey: 'restart-catalog-drift',
    paymentPolicy: paymentPolicyFor(sellerUrl, PAY_TO),
    fetchImpl: (url, init) => (++sellerRequests === 1 ? beforeRestart.app : afterRestart.app).request(url, init),
  }), (error) => error.code === 'SETTLEMENT_EVIDENCE');
  assert.equal(facilitatorCalls, 0);
  assert.equal(providerCalls, 0);
  assert.equal(journal.events.some((event) => event.type === 'payment.signed'), false);
});

test('settled crash recovery converts catalog drift into one terminal full-gross hold', async () => {
  const changedCatalog = structuredClone(EXECUTION_CATALOG);
  changedCatalog.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '15000001';
  const prepared = await settlementCrash({
    executionCatalog: changedCatalog,
    executeSkill: async () => ({ output: 'must not escape', usage: null }),
  });
  const callsAfterCrash = prepared.facilitatorCallCount();
  const eventsAfterCrash = prepared.journal.events.length;
  const changedPayment = JSON.parse(Buffer.from(prepared.xPayment, 'base64').toString('utf8'));
  const persistedNonce = changedPayment.payload.authorization.nonce;
  changedPayment.payload.authorization.nonce = `${persistedNonce.slice(0, -1)}${
    persistedNonce.endsWith('0') ? '1' : '0'
  }`;

  // A settled recovery must still require the exact persisted signed payment,
  // not merely the same payer under the frozen offer.
  const rejected = await prepared.retry(Buffer.from(JSON.stringify(changedPayment)).toString('base64'));
  assert.equal(rejected.status, 409);
  assert.equal(prepared.providerCallCount(), 0);
  assert.equal(prepared.facilitatorCallCount(), callsAfterCrash);
  assert.equal(prepared.journal.events.length, eventsAfterCrash);

  const recovered = await prepared.retry();
  assert.equal(recovered.status, 500);
  const recoveredBody = await recovered.json();
  assert.equal(recoveredBody.output, undefined);
  assert.equal(verifySignedReceipt(recoveredBody.receipt, {
    publicKeyPem: prepared.afterRestart.journal.signingPublicKeyPem,
    keyId: prepared.afterRestart.journal.signingKeyId,
  }), true);
  const receipt = recoveredBody.receipt.receipt;
  assert.equal(receipt.payment.state, 'settled');
  assert.equal(receipt.execution.state, 'failed');
  assert.equal(receipt.execution.failureClass, 'CATALOG_DIGEST_DRIFT');
  assert.equal(receipt.accounting.grossAtomic, '250000');
  assert.equal(receipt.accounting.executionCogs.status, 'unknown');
  assert.equal(receipt.accounting.executionCogs.actualAtomic, null);
  assert.equal(receipt.accounting.royaltyPoolAtomic, '0');
  assert.deepEqual(receipt.accounting.holderCredits, []);
  assert.deepEqual(receipt.accounting.ancestorCredits, []);
  assert.deepEqual(receipt.accounting.journalEntries, [{
    category: 'unresolved-execution-accounting',
    debitAccountId: 'wielder:external-gross',
    creditAccountId: 'hold:execution-accounting-reconciliation',
    amountAtomic: '250000',
  }]);
  assert.equal(prepared.providerCallCount(), 0);
  assert.equal(prepared.facilitatorCallCount(), callsAfterCrash);

  const eventCount = prepared.journal.events.length;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const replay = await prepared.retry();
    assert.equal(replay.status, 500);
    const replayBody = await replay.json();
    assert.equal(replayBody.replayed, true);
    assert.deepEqual(replayBody.receipt, recoveredBody.receipt);
  }
  assert.equal(prepared.providerCallCount(), 0);
  assert.equal(prepared.facilitatorCallCount(), callsAfterCrash);
  assert.equal(prepared.journal.events.length, eventCount);
  assert.equal(prepared.journal.events.filter((event) => event.type === 'execution.finished').length, 1);
  assert.equal(prepared.journal.events.filter((event) => event.type === 'receipt.issued').length, 1);
});

test('settled crash recovery succeeds under unchanged config and replays idempotently', async () => {
  const prepared = await settlementCrash({
    executeSkill: async () => {
      return {
        output: 'recovered output',
        usage: {
          schemaVersion: 2,
          model: 'claude-sonnet-4-6',
          inputTokens: 42,
          outputTokens: 42,
        },
      };
    },
  });
  const callsAfterCrash = prepared.facilitatorCallCount();

  const recovered = await prepared.retry();
  assert.equal(recovered.status, 200);
  const recoveredBody = await recovered.json();
  assert.equal(recoveredBody.output, 'recovered output');
  assert.equal(recoveredBody.receipt.receipt.execution.state, 'succeeded');
  assert.equal(prepared.providerCallCount(), 1);
  assert.equal(prepared.facilitatorCallCount(), callsAfterCrash);

  const eventCount = prepared.journal.events.length;
  const replay = await prepared.retry();
  assert.equal(replay.status, 200);
  const replayBody = await replay.json();
  assert.equal(replayBody.replayed, true);
  assert.deepEqual(replayBody.receipt, recoveredBody.receipt);
  assert.equal(prepared.providerCallCount(), 1);
  assert.equal(prepared.facilitatorCallCount(), callsAfterCrash);
  assert.equal(prepared.journal.events.length, eventCount);
});

test('terminal replay precedes current catalog drift checks and never re-executes', async () => {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  let providerCalls = 0;
  const transport = createMockFacilitatorTransport((url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  const journal = createInvocationJournal({ signer: createReceiptSigner() });
  const beforeRestart = createCollar({
    facilitatorTransport: transport,
    journal,
    executeSkill: async () => {
      providerCalls += 1;
      return {
        output: 'terminal output',
        usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
      };
    },
  });
  const sellerUrl = `http://seller.test/invoke/${SKILL_ID}`;
  const idempotencyKey = 'terminal-replay-before-drift';
  const requestBody = JSON.stringify({ input: 'same frozen request' });
  const first = await payingFetch(throwawayAccount(), sellerUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey,
    paymentPolicy: paymentPolicyFor(sellerUrl, PAY_TO),
    fetchImpl: (url, init) => beforeRestart.app.request(url, init),
  });
  assert.equal(first.res.status, 200);
  const changedCatalog = structuredClone(EXECUTION_CATALOG);
  changedCatalog.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '15000001';
  const afterRestart = createCollar({
    facilitatorTransport: transport,
    journal,
    executionCatalog: changedCatalog,
    executeSkill: async () => { providerCalls += 1; throw new Error('must not run'); },
  });
  const callsAfterFirst = facilitatorCalls;
  const replay = await afterRestart.app.request(sellerUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'X-PAYMENT': first.xPayment,
    },
    body: requestBody,
  });
  assert.equal(replay.status, 200);
  assert.equal((await replay.json()).replayed, true);
  assert.equal(providerCalls, 1);
  assert.equal(facilitatorCalls, callsAfterFirst);
});

test('Anthropic adapter sends frozen model/cap, emits strict v2 usage, and rejects before fetch', async () => {
  const requests = [];
  const executor = createAnthropicExecutor({
    apiKey: 'test-only',
    fetchImpl: async (_url, init) => {
      requests.push(JSON.parse(init.body));
      return new Response(JSON.stringify({
          content: [{ text: 'ok' }],
          usage: { input_tokens: 11, output_tokens: 2 },
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const frozen = { model: 'claude-sonnet-4-6', maxInputTokens: 300, maxOutputTokens: 17 };
  assert.deepEqual(await executor({
    skillContent: 'system', input: 'hello', ...frozen, promptBytes: 11, estimatedInputTokens: 267,
  }), {
    output: 'ok',
    usage: { schemaVersion: 2, model: frozen.model, inputTokens: 11, outputTokens: 2 },
  });
  assert.equal(requests[0].model, frozen.model);
  assert.equal(requests[0].max_tokens, frozen.maxOutputTokens);
  await assert.rejects(executor({
    skillContent: 'x'.repeat(45), input: '', ...frozen, promptBytes: 45, estimatedInputTokens: 301,
  }), (error) => error.code === 'PROMPT_TOKEN_BOUND');
  assert.equal(requests.length, 1);
  assert.throws(() => createAnthropicExecutor({ apiKey: '', fetchImpl: async () => {} }), /API key/);
});

test('Anthropic constructor options cannot raise secure byte or deadline ceilings', () => {
  for (const [option, value, ceiling] of [
    ['timeoutMs', DEFAULT_PROVIDER_TIMEOUT_MS + 1, DEFAULT_PROVIDER_TIMEOUT_MS],
    ['maxResponseBytes', DEFAULT_PROVIDER_RESPONSE_BYTES + 1, DEFAULT_PROVIDER_RESPONSE_BYTES],
  ]) {
    assert.throws(
      () => createAnthropicExecutor({
        apiKey: 'test-only', fetchImpl: async () => {}, [option]: value,
      }),
      new RegExp(`Anthropic ${option} cannot exceed ${ceiling}`),
    );
  }
});

test('Collar constructor cannot raise the outer provider deadline ceiling', () => {
  const facilitatorTransport = createMockFacilitatorTransport(async () => {
    throw new Error('facilitator must not run during construction');
  });
  assert.throws(
    () => createCollar({
      facilitatorTransport,
      providerTimeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS + 1,
    }),
    new RegExp(`providerTimeoutMs cannot exceed ${DEFAULT_PROVIDER_TIMEOUT_MS}`),
  );
});

test('Anthropic executor rejects a JSON-only response double without calling its parser', async () => {
  let jsonCalls = 0;
  const executor = createAnthropicExecutor({
    apiKey: 'test-only',
    fetchImpl: async () => ({
      ok: true,
      async json() {
        jsonCalls += 1;
        return {
          content: [{ text: 'must not be trusted' }],
          usage: { input_tokens: 11, output_tokens: 2 },
        };
      },
    }),
  });
  await assert.rejects(() => executor({
    skillContent: 'system',
    input: 'hello',
    model: 'claude-sonnet-4-6',
    maxInputTokens: 300,
    maxOutputTokens: 17,
    promptBytes: 11,
    estimatedInputTokens: 267,
  }), (error) => (
    error.code === 'UPSTREAM_PROVIDER_RESPONSE_SHAPE'
      && error.message === 'provider response must expose a bounded byte stream'
  ));
  assert.equal(jsonCalls, 0);
});

test('body, complete-prompt, model, and token caps reject before a 402 offer', async () => {
  for (const [body, status, code] of [
    [{ input: 'x'.repeat(4097) }, 413, 'REQUEST_BODY_TOO_LARGE'],
    [{ input: 'x', execution: { maxInputTokens: 300 } }, 400, 'PROMPT_TOKEN_BOUND'],
    [{ input: 'x', execution: { model: 'unlisted-model' } }, 400, 'MODEL_NOT_ALLOWED'],
    [{ input: 'x', execution: { maxOutputTokens: 2049 } }, 400, 'TOKEN_LIMIT'],
  ]) {
    const facilitator = createMockFacilitator();
    const collar = createCollar({
      facilitatorTransport: createMockFacilitatorTransport((url, init) => facilitator.request(url, init)),
    });
    const res = await collar.app.request(`http://collar.test/invoke/${SKILL_ID}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify(body),
    });
    assert.equal(res.status, status);
    assert.equal((await res.json()).code, code);
    assert.equal(collar.journal.events.length, 0);
  }
});

test('above-cap known usage fails with retained COGS, no output, and no Royalty credits', async () => {
  const services = stack({
    executeSkill: async () => ({
      output: 'must not escape',
      usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 16384, outputTokens: 2049 },
    }),
  });
  const { res, body } = await invoke(services.proxy);
  assert.equal(res.status, 500);
  assert.equal(body.output, undefined);
  assert.equal(body.receipt.receipt.payment.state, 'settled');
  assert.equal(body.receipt.receipt.execution.failureClass, 'USAGE_EXCEEDS_QUOTE');
  const accounting = body.receipt.receipt.accounting;
  assert.equal(accounting.allocationState, 'pending_cogs_reconciliation');
  assert.equal(accounting.executionCogs.status, 'known');
  assert.equal(accounting.executionCogs.actualAtomic, '79887');
  assert.equal(accounting.executionCogs.accruedOverrunAtomic, '15');
  assert.equal(accounting.royaltyPoolAtomic, '0');
  assert.deepEqual(accounting.holderCredits, []);
  assert.equal(accounting.journalEntries[0].amountAtomic, accounting.grossAtomic);
});

test('provider failures are sanitized and malformed known usage remains held without output', async () => {
  const secret = 'sk-provider-secret-do-not-leak';
  for (const [executeSkill, failureClass, expectedCogs] of [[
    async () => { throw Object.assign(new Error(`upstream failed ${secret}`), { code: 'ARBITRARY_SECRET_CODE' }); },
    'UPSTREAM_PROVIDER_ERROR',
    'unknown',
  ], [
    async () => ({
      output: 42,
      usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
    }),
    'INVALID_EXECUTOR_RESULT',
    'known',
  ]]) {
    const services = stack({ executeSkill });
    const { res, body } = await invoke(services.proxy);
    assert.equal(res.status, 500);
    assert.equal(body.output, undefined);
    assert.equal(body.receipt.receipt.execution.failureClass, failureClass);
    assert.equal(body.receipt.receipt.accounting.executionCogs.status, expectedCogs);
    assert.equal(body.receipt.receipt.accounting.royaltyPoolAtomic, '0');
    assert.equal(JSON.stringify(body).includes(secret), false);
    assert.equal(JSON.stringify(services.collar.journal.events).includes(secret), false);
  }
});

test('direct artifact serialization fails with known held COGS and emits no artifact bytes', async () => {
  let artifact = null;
  const services = stack({
    executeSkill: async ({ skillContent }) => {
      artifact = skillContent;
      return {
        output: skillContent,
        usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
      };
    },
  });
  const { res, body } = await invoke(services.proxy);
  assert.equal(res.status, 500);
  assert.equal(body.output, undefined);
  assert.equal(body.receipt.receipt.execution.failureClass, 'ARTIFACT_SERIALIZATION');
  assert.equal(body.receipt.receipt.accounting.executionCogs.status, 'known');
  assert.equal(body.receipt.receipt.accounting.executionCogs.actualAtomic, '756');
  assert.equal(JSON.stringify(body).includes(artifact.slice(0, 200)), false);
});

test('Collar snapshots the exact catalog before an executor can mutate caller-owned rates', async () => {
  const catalog = structuredClone(EXECUTION_CATALOG);
  const services = stack({
    executionCatalog: catalog,
    executeSkill: async () => {
      catalog.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '999999999';
      return {
        output: 'safe output',
        usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
      };
    },
  });
  const { res, body } = await invoke(services.proxy);
  assert.equal(res.status, 200);
  assert.equal(body.receipt.receipt.accounting.executionCogs.actualAtomic, '756');
  assert.equal(body.receipt.receipt.quote.executionQuote.catalogDigest, catalogDigest(EXECUTION_CATALOG));
});

test('post-settlement provider deadline finalizes a sanitized unknown-COGS hold', {
  timeout: 1_000,
}, async () => {
  const secret = 'provider-timeout-secret-must-not-leak';
  let providerSignal = null;
  const services = stack({
    providerTimeoutMs: 20,
    executeSkill: async ({ signal }) => {
      providerSignal = signal;
      void secret;
      return new Promise(() => {});
    },
  });
  const { res, body } = await invoke(services.proxy);
  assert.equal(res.status, 500);
  assert.equal(body.output, undefined);
  const receipt = body.receipt.receipt;
  assert.equal(receipt.payment.state, 'settled');
  assert.equal(receipt.execution.state, 'failed');
  assert.equal(receipt.execution.failureClass, 'UPSTREAM_PROVIDER_TIMEOUT');
  assert.equal(receipt.accounting.allocationState, 'pending_cogs_reconciliation');
  assert.equal(receipt.accounting.executionCogs.status, 'unknown');
  assert.equal(receipt.accounting.executionCogs.actualAtomic, null);
  assert.equal(receipt.accounting.royaltyPoolAtomic, '0');
  assert.deepEqual(receipt.accounting.holderCredits, []);
  assert.deepEqual(receipt.accounting.ancestorCredits, []);
  assert.equal(receipt.accounting.journalEntries[0].amountAtomic, receipt.accounting.grossAtomic);
  assert.equal(providerSignal.aborted, true);
  assert.equal(JSON.stringify(body).includes(secret), false);
  assert.equal(JSON.stringify(services.collar.journal.events).includes(secret), false);
});

test('Anthropic executor cancels oversized chunked JSON before buffering provider output', {
  timeout: 1_000,
}, async () => {
  let cancelled = false;
  const executor = createAnthropicExecutor({
    apiKey: 'test-only',
    timeoutMs: 200,
    maxResponseBytes: 64,
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"content":[{"text":"'));
        controller.enqueue(new TextEncoder().encode('provider-secret-'.repeat(8)));
      },
      cancel() { cancelled = true; },
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
  });
  await assert.rejects(() => executor({
    skillContent: 'system',
    input: 'hello',
    model: 'claude-sonnet-4-6',
    maxInputTokens: 300,
    maxOutputTokens: 17,
    promptBytes: 11,
    estimatedInputTokens: 267,
  }), (error) => (
    error.code === 'UPSTREAM_PROVIDER_RESPONSE_TOO_LARGE'
      && error.message === 'provider response exceeds the JSON byte limit'
      && !error.message.includes('secret')
  ));
  assert.equal(cancelled, true);
});

test('Anthropic executor deadline aborts a never-resolving fetch with a stable error', {
  timeout: 1_000,
}, async () => {
  let providerSignal = null;
  const caller = new AbortController();
  const executor = createAnthropicExecutor({
    apiKey: 'test-only',
    timeoutMs: 20,
    fetchImpl: async (_url, init) => {
      providerSignal = init.signal;
      return new Promise(() => {});
    },
  });
  await assert.rejects(() => executor({
    skillContent: 'system',
    input: 'hello',
    model: 'claude-sonnet-4-6',
    maxInputTokens: 300,
    maxOutputTokens: 17,
    promptBytes: 11,
    estimatedInputTokens: 267,
    signal: caller.signal,
  }), (error) => (
    error.code === 'UPSTREAM_PROVIDER_TIMEOUT'
      && error.message === 'provider request timed out'
  ));
  assert.equal(providerSignal.aborted, true);
  assert.equal(caller.signal.aborted, false);
});

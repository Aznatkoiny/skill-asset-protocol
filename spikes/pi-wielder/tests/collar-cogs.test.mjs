import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createAnthropicExecutor,
  createCollar,
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

test('a restarted Collar rejects persisted nonterminal quote drift before facilitator or provider calls', async () => {
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
      return {
        ok: true,
        json: async () => ({
          content: [{ text: 'ok' }],
          usage: { input_tokens: 11, output_tokens: 2 },
        }),
      };
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

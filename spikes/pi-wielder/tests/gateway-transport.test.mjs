import assert from 'node:assert/strict';
import test from 'node:test';

import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { createGateway, MODEL_PRICES_USDC, startGateway } from '../src/gateway.mjs';
import { catalogDigest } from '../src/execution-economics.mjs';
import { payingFetch as policyPayingFetch } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { createMockFacilitatorTransport } from '../src/x402-seller.mjs';
import { paymentPolicyFor } from './payment-policy-fixture.mjs';

const payingFetch = (account, url, init, options = {}) => policyPayingFetch(account, url, init, {
  paymentPolicy: paymentPolicyFor(url),
  ...options,
});

const GATEWAY_URL = 'http://gateway.test/v1/chat/completions';
const PROVIDER_RESPONSE_LIMIT = 1024 * 1024;
const HUMAN_VERIFIED_CATALOG = Object.freeze({
  schemaVersion: 2,
  version: 'gateway-human-verified-test-v1',
  evidenceLabel: 'human_verified',
  source: 'https://provider.example/pricing/2026-07-18',
  asOf: '2026-07-18T00:00:00.000Z',
  models: Object.freeze({
    'claude-sonnet-4-6': Object.freeze({
      provider: 'anthropic',
      inputAtomicPerMillionTokens: '1000000',
      outputAtomicPerMillionTokens: '2000000',
      maxInputTokens: 4096,
      maxOutputTokens: 64,
    }),
    'gpt-5.2': Object.freeze({
      provider: 'openai',
      inputAtomicPerMillionTokens: '1000000',
      outputAtomicPerMillionTokens: '2000000',
      maxInputTokens: 4096,
      maxOutputTokens: 64,
    }),
  }),
});
const LIVE_APPROVAL = Object.freeze({
  catalogDigest: catalogDigest(HUMAN_VERIFIED_CATALOG),
  spendCapAtomic: '5000',
});
const SYNTHETIC_PROVIDER_KEYS = Object.freeze({
  anthropic: 'synthetic-anthropic-test-key',
  openai: 'synthetic-openai-test-key',
});

function facilitatorTransport() {
  const facilitator = createMockFacilitator();
  return createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
}

function liveGatewayOptions(providerFetch, overrides = {}) {
  return {
    facilitatorTransport: facilitatorTransport(),
    mockLlm: false,
    allowLiveProvider: true,
    providerCatalog: structuredClone(HUMAN_VERIFIED_CATALOG),
    liveApproval: { ...LIVE_APPROVAL },
    providerFetch,
    providerApiKeys: { ...SYNTHETIC_PROVIDER_KEYS },
    providerTimeoutMs: 1_000,
    maxProviderResponseBytes: PROVIDER_RESPONSE_LIMIT,
    ...overrides,
  };
}

function openAiCompletion({ promptTokens = 2, completionTokens = 3 } = {}) {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion',
    created: 1,
    model: 'gpt-5.2',
    choices: [{
      index: 0,
      message: { role: 'assistant', content: 'provider output' },
      finish_reason: 'stop',
    }],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    },
  };
}

function anthropicCompletion({ inputTokens = 2, outputTokens = 3 } = {}) {
  return {
    id: 'msg-test',
    type: 'message',
    role: 'assistant',
    model: 'claude-sonnet-4-6',
    content: [{ type: 'text', text: 'provider output' }],
    stop_reason: 'end_turn',
    usage: {
      input_tokens: inputTokens,
      output_tokens: outputTokens,
    },
  };
}

async function paidGatewayRequest(gateway, body, idempotencyKey) {
  return payingFetch(throwawayAccount(), GATEWAY_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }, {
    fetchImpl: (url, init) => gateway.request(url, init),
    idempotencyKey,
  });
}

async function withSyntheticGlobalProvider(providerFetch, operation, { unsetMock = false } = {}) {
  const originalFetch = globalThis.fetch;
  const originalOpenAiKey = process.env.OPENAI_API_KEY;
  const originalAnthropicKey = process.env.ANTHROPIC_API_KEY;
  const originalMock = process.env.MOCK_LLM;
  globalThis.fetch = providerFetch;
  process.env.OPENAI_API_KEY = SYNTHETIC_PROVIDER_KEYS.openai;
  process.env.ANTHROPIC_API_KEY = SYNTHETIC_PROVIDER_KEYS.anthropic;
  if (unsetMock) delete process.env.MOCK_LLM;
  try {
    return await operation();
  } finally {
    globalThis.fetch = originalFetch;
    if (originalOpenAiKey === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = originalOpenAiKey;
    if (originalAnthropicKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = originalAnthropicKey;
    if (originalMock === undefined) delete process.env.MOCK_LLM;
    else process.env.MOCK_LLM = originalMock;
  }
}

test('gateway prices are decimal strings and the injected transport stays in process', async () => {
  assert.ok(Object.values(MODEL_PRICES_USDC).every((price) => typeof price === 'string'));
  const facilitator = createMockFacilitator();
  const facilitatorTransport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
  const gateway = createGateway({ facilitatorTransport, mockLlm: true });
  const paid = await payingFetch(throwawayAccount(), 'http://gateway.test/v1/chat/completions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      messages: [{ role: 'user', content: 'price this request' }],
    }),
  }, {
    fetchImpl: (url, init) => gateway.request(url, init),
    idempotencyKey: 'idem-gateway',
  });
  assert.equal(paid.res.status, 200);
  assert.equal(paid.amountAtomic, '41000');
  assert.equal(paid.amountDisplay, '0.041000');
});

test('gateway rejects an unapproved structural transport or legacy facilitator URL', () => {
  assert.throws(() => createGateway({
    facilitatorTransport: { mode: 'mock', baseUrl: 'http://facilitator.invalid', fetchImpl: fetch },
    mockLlm: true,
  }), /approved live or injected-mock/);
  assert.throws(() => createGateway({ facilitatorUrl: 'https://evil.test', mockLlm: true }), /facilitatorTransport/);
});

test('gateway defaults to mock execution and never calls a provider when MOCK_LLM is unset', async () => {
  let providerCalls = 0;
  const providerFetch = async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion());
  };
  await withSyntheticGlobalProvider(providerFetch, async () => {
    const gateway = createGateway({ facilitatorTransport: facilitatorTransport() });
    const paid = await paidGatewayRequest(gateway, {
      model: 'gpt-5.2',
      messages: [{ role: 'user', content: 'stay offline' }],
      max_tokens: 8,
    }, 'idem-gateway-default-mock');
    assert.equal(paid.res.status, 200);
    assert.equal(providerCalls, 0);
    const body = await paid.res.json();
    assert.match(body.choices[0].message.content, /^\[mock gpt-5\.2\]/);
  }, { unsetMock: true });
});

test('live gateway construction requires the explicit gate, human catalog digest, and provider spend cap', () => {
  let providerCalls = 0;
  const providerFetch = async () => {
    providerCalls += 1;
    throw new Error('must not fetch during approval');
  };
  assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
    allowLiveProvider: false,
  })), /explicit live provider gate/i);
  for (const nonBooleanGate of [1, 'true', {}, []]) {
    assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
      allowLiveProvider: nonBooleanGate,
    })), /explicit live provider gate/i);
  }
  assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
    liveApproval: null,
  })), /live approval/i);
  assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
    liveApproval: { ...LIVE_APPROVAL, catalogDigest: `sha256:${'0'.repeat(64)}` },
  })), /digest/i);
  assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
    liveApproval: { ...LIVE_APPROVAL, spendCapAtomic: '4159' },
  })), /spend cap/i);
  assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
    providerCatalog: {
      ...structuredClone(HUMAN_VERIFIED_CATALOG),
      evidenceLabel: 'synthetic_config',
      source: null,
      asOf: null,
    },
  })), /human_verified/i);
  assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
    maxProviderResponseBytes: PROVIDER_RESPONSE_LIMIT + 1,
  })), /must not exceed one MiB/i);
  assert.throws(() => createGateway(liveGatewayOptions(providerFetch, {
    providerTimeoutMs: 30_001,
  })), /must not exceed 30000 milliseconds/i);
  assert.equal(providerCalls, 0);
});

test('gateway rejects unknown models and request token bounds before offering payment', async () => {
  let providerCalls = 0;
  const gateway = createGateway(liveGatewayOptions(async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion());
  }));
  const framingAllowanceCase = {
    model: 'gpt-5.2',
    messages: [{ role: 'user', content: 'x'.repeat(3_200) }],
    max_tokens: 8,
  };
  const framingAllowanceBytes = Buffer.byteLength(JSON.stringify(framingAllowanceCase));
  assert.ok(framingAllowanceBytes < HUMAN_VERIFIED_CATALOG.models['gpt-5.2'].maxInputTokens);
  assert.ok(framingAllowanceBytes + 1_024 > HUMAN_VERIFIED_CATALOG.models['gpt-5.2'].maxInputTokens);
  const invalidBodies = [
    { model: 'attacker-model', messages: [{ role: 'user', content: 'reject this model' }], max_tokens: 8 },
    { model: 'gpt-5.2', messages: [{ role: 'user', content: 'reject this limit' }], max_tokens: 65 },
    {
      model: 'gpt-5.2',
      messages: [{ role: 'user', content: 'reject conflicting limits' }],
      max_tokens: 8,
      max_completion_tokens: 8,
    },
    { model: 'gpt-5.2', messages: [{ role: 'user', content: 'x'.repeat(5000) }], max_tokens: 8 },
    framingAllowanceCase,
  ];
  for (let index = 0; index < invalidBodies.length; index += 1) {
    const response = await gateway.request(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': `idem-gateway-invalid-${index}`,
      },
      body: JSON.stringify(invalidBodies[index]),
    });
    assert.equal(response.status, 400, `invalid case ${index}`);
    assert.match((await response.json()).code, /MODEL_NOT_ALLOWED|TOKEN_LIMIT|PROMPT_TOKEN_BOUND/);
  }
  assert.equal(providerCalls, 0);
});

test('gateway rejects malformed message structure before offering payment', async () => {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  let providerCalls = 0;
  const gateway = createGateway(liveGatewayOptions(async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion());
  }, { facilitatorTransport: transport }));

  const invalidMessages = [
    {},
    [],
    [null],
    [{ content: 'missing role' }],
    [{ role: 'attacker', content: 'unsupported role' }],
    [{ role: 'user' }],
    [{ role: 'user', content: {} }],
    [{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'https://example.test' } }] }],
    [{ role: 'user', content: [{ type: 'text' }] }],
  ];
  for (let index = 0; index < invalidMessages.length; index += 1) {
    const response = await gateway.request(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': `idem-gateway-malformed-messages-${index}`,
      },
      body: JSON.stringify({ model: 'gpt-5.2', messages: invalidMessages[index], max_tokens: 8 }),
    });
    assert.equal(response.status, 400, `invalid message case ${index}`);
    assert.deepEqual(await response.json(), {
      error: 'gateway request is invalid',
      code: 'REQUEST_SCHEMA',
    });
  }
  for (const [index, body] of ['{', 'null', '[]'].entries()) {
    const response = await gateway.request(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': `idem-gateway-malformed-json-${index}`,
      },
      body,
    });
    assert.equal(response.status, 400, `invalid JSON case ${index}`);
    assert.deepEqual(await response.json(), {
      error: 'gateway request is invalid',
      code: 'REQUEST_SCHEMA',
    });
  }
  assert.equal(facilitatorCalls, 0);
  assert.equal(providerCalls, 0);
});

test('gateway rejects malformed tool definitions before offering payment', async () => {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  let providerCalls = 0;
  const gateway = createGateway(liveGatewayOptions(async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion());
  }, { facilitatorTransport: transport }));
  const invalidTools = [
    {},
    [{}],
    [null],
    [{ type: 'custom', function: { name: 'lookup', parameters: {} } }],
    [{ type: 'function' }],
    [{ type: 'function', function: [] }],
    [{ type: 'function', function: { parameters: {} } }],
    [{ type: 'function', function: { name: '', parameters: {} } }],
    [{ type: 'function', function: { name: 'lookup', parameters: [] } }],
    [{ type: 'function', function: { name: 'lookup', parameters: {}, description: 7 } }],
    [{ type: 'function', function: { name: 'lookup', parameters: {}, strict: 'true' } }],
    [{ type: 'function', function: { name: 'lookup', parameters: {}, unsupported: true } }],
    [{ type: 'function', function: { name: 'lookup', parameters: {} }, unsupported: true }],
  ];

  for (let index = 0; index < invalidTools.length; index += 1) {
    const response = await gateway.request(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': `idem-gateway-malformed-tools-${index}`,
      },
      body: JSON.stringify({
        model: 'gpt-5.2',
        messages: [{ role: 'user', content: 'use a tool' }],
        tools: invalidTools[index],
        max_tokens: 8,
      }),
    });
    assert.equal(response.status, 400, `invalid tool case ${index}`);
    assert.deepEqual(await response.json(), {
      error: 'gateway request is invalid',
      code: 'REQUEST_SCHEMA',
    });
  }
  assert.equal(facilitatorCalls, 0);
  assert.equal(providerCalls, 0);
});

test('gateway rejects malformed tool-call messages before offering payment', async () => {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  let providerCalls = 0;
  const gateway = createGateway(liveGatewayOptions(async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion());
  }, { facilitatorTransport: transport }));
  const invalidMessages = [
    [{ role: 'assistant', content: null }],
    [{ role: 'assistant', content: null, tool_calls: {} }],
    [{ role: 'assistant', content: null, tool_calls: [] }],
    [{ role: 'assistant', content: null, tool_calls: [{}] }],
    [{ role: 'assistant', content: null, tool_calls: [{
      id: 'call-1', type: 'custom', function: { name: 'lookup', arguments: '{}' },
    }] }],
    [{ role: 'assistant', content: null, tool_calls: [{
      id: '', type: 'function', function: { name: 'lookup', arguments: '{}' },
    }] }],
    [{ role: 'assistant', content: null, tool_calls: [{
      id: 'call-1', type: 'function', function: { name: 'lookup', arguments: '{not-json' },
    }] }],
    [{ role: 'assistant', content: null, tool_calls: [{
      id: 'call-1', type: 'function', function: { name: 'lookup', arguments: '[]' },
    }] }],
    [{ role: 'assistant', content: null, tool_calls: [{
      id: 'call-1', type: 'function', function: { name: 'lookup', arguments: {} },
    }] }],
    [{ role: 'assistant', content: null, tool_calls: [{
      id: 'call-1', type: 'function', function: { name: 'lookup', arguments: '{}', extra: true },
    }] }],
    [{ role: 'tool', content: 'result' }],
    [{ role: 'tool', content: 'result', tool_call_id: '' }],
    [{ role: 'tool', content: 'result', tool_call_id: 'x'.repeat(257) }],
  ];

  for (let index = 0; index < invalidMessages.length; index += 1) {
    const response = await gateway.request(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': `idem-gateway-malformed-tool-calls-${index}`,
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', messages: invalidMessages[index], max_tokens: 8 }),
    });
    assert.equal(response.status, 400, `invalid tool-call message case ${index}`);
    assert.deepEqual(await response.json(), {
      error: 'gateway request is invalid',
      code: 'REQUEST_SCHEMA',
    });
  }
  assert.equal(facilitatorCalls, 0);
  assert.equal(providerCalls, 0);
});

test('gateway rejects unknown and malformed provider options before offering payment', async () => {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  let providerCalls = 0;
  const gateway = createGateway(liveGatewayOptions(async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion());
  }, { facilitatorTransport: transport }));
  const openAiBase = {
    model: 'gpt-5.2',
    messages: [{ role: 'user', content: 'validate options' }],
    max_tokens: 8,
  };
  const anthropicBase = { ...openAiBase, model: 'claude-sonnet-4-6' };
  const invalidBodies = [
    { ...openAiBase, unknown_option: true },
    { ...openAiBase, stream: 'false' },
    { ...openAiBase, temperature: '0.5' },
    { ...openAiBase, temperature: 2.1 },
    { ...anthropicBase, temperature: 0.4 },
    { ...anthropicBase, temperature: 1.1 },
    { ...openAiBase, top_p: -0.1 },
    { ...openAiBase, top_p: 1.1 },
    { ...anthropicBase, top_p: 0.8 },
    { ...openAiBase, stop: {} },
    { ...openAiBase, stop: [] },
    { ...openAiBase, stop: ['', 'valid'] },
    { ...openAiBase, stop: ['1', '2', '3', '4', '5'] },
    { ...openAiBase, presence_penalty: 2.1 },
    { ...openAiBase, frequency_penalty: -2.1 },
    { ...anthropicBase, presence_penalty: 0 },
    { ...openAiBase, response_format: [] },
    { ...openAiBase, response_format: { type: 'unknown' } },
    { ...openAiBase, response_format: { type: 'json_schema', json_schema: {} } },
    { ...anthropicBase, response_format: { type: 'json_object' } },
    { ...openAiBase, seed: 1.5 },
    { ...anthropicBase, seed: 1 },
    { ...openAiBase, user: {} },
    { ...anthropicBase, user: 'wielder-1' },
    {
      ...anthropicBase,
      messages: [
        { role: 'system', content: 'system only' },
        { role: 'developer', content: 'still no provider message' },
      ],
    },
    {
      ...anthropicBase,
      tools: [{
        type: 'function',
        function: { name: 'lookup', parameters: {}, strict: true },
      }],
    },
    { ...openAiBase, tool_choice: 'attacker' },
    { ...anthropicBase, tool_choice: 'auto' },
    { ...openAiBase, tool_choice: { type: 'function', function: {} } },
    { ...openAiBase, tool_choice: { type: 'function', function: { name: 'missing_tool' } } },
  ];

  for (let index = 0; index < invalidBodies.length; index += 1) {
    const response = await gateway.request(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': `idem-gateway-malformed-options-${index}`,
      },
      body: JSON.stringify(invalidBodies[index]),
    });
    assert.equal(response.status, 400, `invalid option case ${index}`);
    assert.deepEqual(await response.json(), {
      error: 'gateway request is invalid',
      code: 'REQUEST_SCHEMA',
    });
  }
  assert.equal(facilitatorCalls, 0);
  assert.equal(providerCalls, 0);
});

test('approved provider fetch receives redirect refusal and a composed request signal', async () => {
  let capturedUrl = null;
  let capturedInit = null;
  const providerFetch = async (url, init) => {
    capturedUrl = url;
    capturedInit = init;
    return Response.json(openAiCompletion());
  };
  await withSyntheticGlobalProvider(providerFetch, async () => {
    const gateway = createGateway(liveGatewayOptions(providerFetch));
    const paid = await paidGatewayRequest(gateway, {
      model: 'gpt-5.2',
      messages: [{ role: 'user', content: 'bounded request' }],
      max_tokens: 8,
    }, 'idem-gateway-approved-live');
    assert.equal(paid.res.status, 200);
    assert.equal(capturedUrl, 'https://api.openai.com/v1/chat/completions');
    assert.equal(capturedInit.redirect, 'error');
    assert.ok(capturedInit.signal instanceof AbortSignal);
    assert.equal(capturedInit.signal.aborted, false);
  });
});

test('gateway normalizes canonical Pi text parts for an OpenAI provider', async () => {
  let capturedBody = null;
  const providerFetch = async (_url, init) => {
    capturedBody = JSON.parse(init.body);
    return Response.json(openAiCompletion());
  };
  const gateway = createGateway(liveGatewayOptions(providerFetch));
  const messages = [
    {
      role: 'developer',
      name: 'planner',
      content: [{ type: 'input_text', text: 'Use the weather Skill.' }],
    },
    { role: 'user', content: [{ type: 'text', text: 'Weather in Paris?' }] },
    {
      role: 'assistant',
      content: null,
      tool_calls: [{
        id: 'call_weather_1',
        type: 'function',
        function: { name: 'lookup_weather', arguments: '{not-json' },
      }],
    },
    {
      role: 'tool',
      tool_call_id: 'call_weather_1',
      content: [{ type: 'output_text', text: 'Sunny' }],
    },
  ];
  const tools = [{
    type: 'function',
    function: {
      name: 'lookup_weather',
      description: 'Look up weather',
      parameters: {
        type: 'object',
        properties: { city: { type: 'string' } },
        required: ['city'],
        additionalProperties: false,
      },
      strict: true,
    },
  }];

  const paid = await paidGatewayRequest(gateway, {
    model: 'gpt-5.2',
    messages,
    tools,
    tool_choice: { type: 'function', function: { name: 'lookup_weather' } },
    temperature: 0.5,
    top_p: 0.9,
    stop: ['DONE'],
    presence_penalty: 0.25,
    frequency_penalty: -0.25,
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: 'weather_result',
        schema: { type: 'object', properties: { weather: { type: 'string' } } },
        strict: true,
      },
    },
    seed: 7,
    user: 'wielder-1',
    max_completion_tokens: 8,
    stream: true,
  }, 'idem-gateway-valid-openai-tool-shape');

  assert.equal(paid.res.status, 200);
  assert.deepEqual(capturedBody, {
    messages: [
      {
        role: 'developer',
        name: 'planner',
        content: [{ type: 'text', text: 'Use the weather Skill.' }],
      },
      { role: 'user', content: [{ type: 'text', text: 'Weather in Paris?' }] },
      {
        role: 'assistant',
        content: null,
        tool_calls: [{
          id: 'call_weather_1',
          type: 'function',
          function: { name: 'lookup_weather', arguments: '{not-json' },
        }],
      },
      {
        role: 'tool',
        tool_call_id: 'call_weather_1',
        content: [{ type: 'text', text: 'Sunny' }],
      },
    ],
    tools,
    tool_choice: { type: 'function', function: { name: 'lookup_weather' } },
    temperature: 0.5,
    top_p: 0.9,
    stop: ['DONE'],
    presence_penalty: 0.25,
    frequency_penalty: -0.25,
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: 'weather_result',
        schema: { type: 'object', properties: { weather: { type: 'string' } } },
        strict: true,
      },
    },
    seed: 7,
    user: 'wielder-1',
    model: 'gpt-5.2',
    max_completion_tokens: 8,
    n: 1,
    stream: false,
  });
});

test('gateway translates canonical Pi tool messages for an Anthropic provider', async () => {
  let capturedUrl = null;
  let capturedBody = null;
  const providerFetch = async (url, init) => {
    capturedUrl = url;
    capturedBody = JSON.parse(init.body);
    return Response.json(anthropicCompletion());
  };
  const gateway = createGateway(liveGatewayOptions(providerFetch));

  const paid = await paidGatewayRequest(gateway, {
    model: 'claude-sonnet-4-6',
    messages: [
      { role: 'developer', content: [{ type: 'input_text', text: 'Developer policy' }] },
      { role: 'system', content: 'System policy' },
      { role: 'user', content: [{ type: 'text', text: 'Weather in Paris?' }] },
      {
        role: 'assistant',
        content: [{ type: 'output_text', text: 'I will check.' }],
        tool_calls: [{
          id: 'call_weather_2',
          type: 'function',
          function: { name: 'lookup_weather', arguments: '{"city":"Paris"}' },
        }],
      },
      {
        role: 'tool',
        tool_call_id: 'call_weather_2',
        content: [{ type: 'input_text', text: 'Sunny' }],
      },
    ],
    tools: [{
      type: 'function',
      function: {
        name: 'lookup_weather',
        description: 'Look up weather',
        parameters: { type: 'object', properties: { city: { type: 'string' } } },
      },
    }],
    tool_choice: 'required',
    stop: ['DONE'],
    max_tokens: 8,
  }, 'idem-gateway-valid-anthropic-tool-shape');

  assert.equal(paid.res.status, 200);
  assert.equal(capturedUrl, 'https://api.anthropic.com/v1/messages');
  assert.deepEqual(capturedBody, {
    model: 'claude-sonnet-4-6',
    max_tokens: 8,
    stop_sequences: ['DONE'],
    system: 'Developer policy\nSystem policy',
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'Weather in Paris?' }] },
      {
        role: 'assistant',
        content: [
          { type: 'text', text: 'I will check.' },
          {
            type: 'tool_use',
            id: 'call_weather_2',
            name: 'lookup_weather',
            input: { city: 'Paris' },
          },
        ],
      },
      {
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: 'call_weather_2', content: 'Sunny' }],
      },
    ],
    tools: [{
      name: 'lookup_weather',
      description: 'Look up weather',
      input_schema: { type: 'object', properties: { city: { type: 'string' } } },
    }],
    tool_choice: { type: 'any' },
  });
});

test('live provider spend approval is a cumulative process-run budget', async () => {
  let providerCalls = 0;
  const providerFetch = async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion({ promptTokens: 998, completionTokens: 1 }));
  };
  const gateway = createGateway(liveGatewayOptions(providerFetch));
  const body = {
    model: 'gpt-5.2',
    messages: [{ role: 'user', content: 'bounded cumulative spend' }],
    max_tokens: 8,
  };

  const first = await paidGatewayRequest(gateway, body, 'idem-gateway-spend-first');
  assert.equal(first.res.status, 200);
  assert.equal(providerCalls, 1);

  const second = await gateway.request(GATEWAY_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'idempotency-key': 'idem-gateway-spend-second',
    },
    body: JSON.stringify(body),
  });
  assert.equal(second.status, 503);
  assert.deepEqual(await second.json(), {
    error: 'live provider spend budget cannot cover this request',
    code: 'PROVIDER_SPEND_CAP',
  });
  assert.equal(providerCalls, 1);
});

test('concurrent paid retries reserve provider budget before facilitator settlement', async () => {
  const facilitator = createMockFacilitator();
  let verifyCalls = 0;
  let settleCalls = 0;
  let releaseVerifiers;
  const bothVerifiersReady = new Promise((resolve) => { releaseVerifiers = resolve; });
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const operation = new URL(url).pathname;
    if (operation === '/verify') {
      verifyCalls += 1;
      if (verifyCalls === 2) releaseVerifiers();
      await bothVerifiersReady;
    }
    if (operation === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  let providerCalls = 0;
  const providerFetch = async () => {
    providerCalls += 1;
    return Response.json(openAiCompletion({ promptTokens: 998, completionTokens: 1 }));
  };
  const gateway = createGateway(liveGatewayOptions(providerFetch, {
    facilitatorTransport: transport,
  }));
  const body = {
    model: 'gpt-5.2',
    messages: [{ role: 'user', content: 'concurrent budget claim' }],
    max_tokens: 8,
  };
  const outcomes = await Promise.allSettled([
    paidGatewayRequest(gateway, body, 'idem-gateway-concurrent-spend-a'),
    paidGatewayRequest(gateway, body, 'idem-gateway-concurrent-spend-b'),
  ]);
  const fulfilled = outcomes.filter((outcome) => outcome.status === 'fulfilled');
  const rejected = outcomes.filter((outcome) => outcome.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(fulfilled[0].value.res.status, 200);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.code, 'SETTLEMENT_EVIDENCE');
  assert.equal(verifyCalls, 2);
  assert.equal(settleCalls, 1);
  assert.equal(providerCalls, 1);
});

test('provider wall-clock deadline aborts an ignoring fetch and returns only a stable error', async () => {
  let providerSignal = null;
  let providerCalls = 0;
  const providerFetch = async (_url, init) => {
    providerCalls += 1;
    providerSignal = init.signal;
    return new Promise((resolve) => {
      setTimeout(() => resolve(Response.json(openAiCompletion())), 50);
    });
  };
  await withSyntheticGlobalProvider(providerFetch, async () => {
    const gateway = createGateway(liveGatewayOptions(providerFetch, { providerTimeoutMs: 5 }));
    const started = performance.now();
    const paid = await paidGatewayRequest(gateway, {
      model: 'gpt-5.2', messages: [{ role: 'user', content: 'time out' }], max_tokens: 8,
    }, 'idem-gateway-provider-timeout');
    assert.ok(performance.now() - started < 45);
    assert.equal(paid.res.status, 504);
    assert.equal(providerSignal.aborted, true);
    assert.deepEqual(await paid.res.json(), {
      error: 'upstream provider timed out',
      code: 'UPSTREAM_PROVIDER_TIMEOUT',
    });
    const nextOffer = await gateway.request(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': 'idem-gateway-after-provider-timeout',
      },
      body: JSON.stringify({
        model: 'gpt-5.2',
        messages: [{ role: 'user', content: 'budget is held' }],
        max_tokens: 8,
      }),
    });
    assert.equal(nextOffer.status, 503);
    assert.deepEqual(await nextOffer.json(), {
      error: 'live provider spend budget cannot cover this request',
      code: 'PROVIDER_SPEND_CAP',
    });
    assert.equal(providerCalls, 1);
  });
});

test('provider response is cancelled on the first streamed byte over one MiB', async () => {
  let cancelled = false;
  const providerFetch = async () => ({
    ok: true,
    status: 200,
    headers: new Headers(),
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(Buffer.alloc(PROVIDER_RESPONSE_LIMIT, 0x20));
        controller.enqueue(Buffer.from('{}'));
      },
      cancel() { cancelled = true; },
    }),
    async json() { return {}; },
  });
  await withSyntheticGlobalProvider(providerFetch, async () => {
    const gateway = createGateway(liveGatewayOptions(providerFetch));
    const paid = await paidGatewayRequest(gateway, {
      model: 'gpt-5.2', messages: [{ role: 'user', content: 'oversized response' }], max_tokens: 8,
    }, 'idem-gateway-provider-oversize');
    assert.equal(paid.res.status, 502);
    assert.equal(cancelled, true);
    assert.deepEqual(await paid.res.json(), {
      error: 'upstream provider response exceeds the byte limit',
      code: 'UPSTREAM_PROVIDER_RESPONSE_TOO_LARGE',
    });
  });
});

test('provider HTTP errors cancel without consuming or exposing the raw response body', async () => {
  let textCalls = 0;
  let cancelled = false;
  const providerFetch = async () => ({
    ok: false,
    status: 429,
    headers: new Headers({ 'content-type': 'application/json' }),
    body: new ReadableStream({
      cancel() { cancelled = true; },
    }),
    async text() {
      textCalls += 1;
      return 'provider-secret-response-body';
    },
  });
  await withSyntheticGlobalProvider(providerFetch, async () => {
    const gateway = createGateway(liveGatewayOptions(providerFetch));
    const paid = await paidGatewayRequest(gateway, {
      model: 'gpt-5.2', messages: [{ role: 'user', content: 'provider failure' }], max_tokens: 8,
    }, 'idem-gateway-provider-http-error');
    assert.equal(paid.res.status, 502);
    assert.equal(textCalls, 0);
    assert.equal(cancelled, true);
    const body = await paid.res.json();
    assert.deepEqual(body, {
      error: 'upstream provider request failed',
      code: 'UPSTREAM_PROVIDER_HTTP',
    });
    assert.doesNotMatch(JSON.stringify(body), /provider-secret/);
  });
});

test('provider usage outside the approved request bounds is rejected without output', async () => {
  const providerFetch = async () => Response.json(openAiCompletion({ promptTokens: 4097 }));
  await withSyntheticGlobalProvider(providerFetch, async () => {
    const gateway = createGateway(liveGatewayOptions(providerFetch));
    const paid = await paidGatewayRequest(gateway, {
      model: 'gpt-5.2', messages: [{ role: 'user', content: 'invalid usage' }], max_tokens: 8,
    }, 'idem-gateway-provider-usage-overrun');
    assert.equal(paid.res.status, 502);
    assert.deepEqual(await paid.res.json(), {
      error: 'upstream provider usage is invalid',
      code: 'UPSTREAM_PROVIDER_USAGE',
    });
  });
});

test('gateway listener binds only IPv4 loopback and closes cleanly', async () => {
  const facilitator = createMockFacilitator();
  const gateway = await startGateway({
    facilitatorTransport: createMockFacilitatorTransport(
      (url, init) => facilitator.request(url, init),
    ),
    mockLlm: true,
  });
  try {
    assert.equal(gateway.address, '127.0.0.1');
    assert.equal(new URL(gateway.url).hostname, '127.0.0.1');
    assert.equal((await fetch(`${gateway.url}/healthz`)).status, 200);
  } finally {
    await gateway.close();
  }
});

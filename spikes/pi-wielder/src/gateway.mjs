// gateway.mjs — a simulated x402 inference reseller (the OTHER asset class).
//
// Live x402 inference gateways (Router402, tx402.ai, BlockRun's ClawRouter)
// are mainnet-only, and no first-party model API accepts x402 yet. So for a
// testnet spike we run our own: an OpenAI-compatible /v1/chat/completions
// that is 402-gated exactly like theirs, and that fulfills the request with
// local API keys (Anthropic for claude-*, OpenAI for gpt-*) — or canned
// completions under MOCK_LLM=1.
//
// Economically this leg is plain pass-through: no royalty table, no split.
// The Wielder displays this observation beside its pinned Collar receipt view;
// that payer-side display is useful, but it is not a shared accounting authority.

import { pathToFileURL } from 'node:url';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import {
  assertLiveCatalogApproval,
  catalogDigest,
  usageCostAtomic,
} from './execution-economics.mjs';
import {
  readJsonBody,
  RuntimeBoundaryError,
  withWallClockDeadline,
} from './runtime-boundaries.mjs';
import {
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
  x402Paywall,
  x402RequestBodyBytes,
  x402RequestBodyText,
} from './x402-seller.mjs';

// Flat per-call testnet prices by model family (real resellers price per
// token; per-call keeps the 402 requirements computable before inference).
export const MODEL_PRICES_USDC = Object.freeze({ claude: '0.041', gpt: '0.087', default: '0.05' });
export const MAX_GATEWAY_REQUEST_BODY_BYTES = 1024 * 1024;
export const DEFAULT_GATEWAY_PROVIDER_TIMEOUT_MS = 30_000;
export const MAX_GATEWAY_PROVIDER_RESPONSE_BYTES = 1024 * 1024;
export const GATEWAY_PROVIDER_FRAMING_TOKEN_ALLOWANCE = 1_024;
export const GATEWAY_EXECUTION_CATALOG = deepFreeze({
  schemaVersion: 2,
  version: 'synthetic-gateway-2026-07-18-v1',
  evidenceLabel: 'synthetic_config',
  source: null,
  asOf: null,
  models: {
    'claude-sonnet-4-6': {
      provider: 'anthropic',
      inputAtomicPerMillionTokens: '3000000',
      outputAtomicPerMillionTokens: '15000000',
      maxInputTokens: 200_000,
      maxOutputTokens: 8_192,
    },
    'gpt-5.2': {
      provider: 'openai',
      inputAtomicPerMillionTokens: '1000000',
      outputAtomicPerMillionTokens: '1000000',
      maxInputTokens: 128_000,
      maxOutputTokens: 8_192,
    },
    // Retained only for the offline protocol e2e's generic mock challenge.
    'gpt-x': {
      provider: 'openai',
      inputAtomicPerMillionTokens: '1000000',
      outputAtomicPerMillionTokens: '1000000',
      maxInputTokens: 128_000,
      maxOutputTokens: 8_192,
    },
  },
});

const LIVE_PROVIDERS = new Set(['anthropic', 'openai']);
const GATEWAY_MESSAGE_ROLES = new Set(['assistant', 'developer', 'system', 'tool', 'user']);
const GATEWAY_SYSTEM_MESSAGE_ROLES = new Set(['developer', 'system']);
const GATEWAY_TEXT_PART_TYPES = new Set(['input_text', 'output_text', 'text']);
const MAX_GATEWAY_PARTICIPANT_NAME_CHARACTERS = 64;
const MAX_GATEWAY_TOOL_CALL_ID_CHARACTERS = 256;
const GATEWAY_FUNCTION_NAME = /^[A-Za-z0-9_-]{1,64}$/;
const GATEWAY_REQUEST_KEYS = new Set([
  'frequency_penalty', 'max_completion_tokens', 'max_tokens', 'messages', 'model',
  'presence_penalty', 'response_format', 'seed', 'stop', 'stream', 'temperature',
  'tool_choice', 'tools', 'top_p', 'user',
]);

class GatewayBoundaryError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'GatewayBoundaryError';
    this.code = code;
    this.status = status;
  }
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function positiveLimit(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function gatewayFailure(code, message, status) {
  throw new GatewayBoundaryError(code, message, status);
}

function plainJsonObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.has(key));
}

function boundedString(value, maximumCharacters) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximumCharacters;
}

function supportedMessageContent(content) {
  if (typeof content === 'string') return true;
  return Array.isArray(content)
    && content.length > 0
    && content.every((part) => plainJsonObject(part)
      && hasOnlyKeys(part, new Set(['text', 'type']))
      && GATEWAY_TEXT_PART_TYPES.has(part.type)
      && typeof part.text === 'string');
}

function supportedToolArguments(value) {
  return typeof value === 'string';
}

function supportedAssistantToolCalls(message) {
  if (!Object.hasOwn(message, 'tool_calls')) return null;
  if (!Array.isArray(message.tool_calls) || message.tool_calls.length === 0) return false;
  return message.tool_calls.every((toolCall) => plainJsonObject(toolCall)
    && hasOnlyKeys(toolCall, new Set(['function', 'id', 'type']))
    && boundedString(toolCall.id, MAX_GATEWAY_TOOL_CALL_ID_CHARACTERS)
    && toolCall.type === 'function'
    && plainJsonObject(toolCall.function)
    && hasOnlyKeys(toolCall.function, new Set(['arguments', 'name']))
    && typeof toolCall.function.name === 'string'
    && GATEWAY_FUNCTION_NAME.test(toolCall.function.name)
    && supportedToolArguments(toolCall.function.arguments));
}

function assertGatewayMessages(body) {
  if (!Object.hasOwn(body, 'messages')
      || !Array.isArray(body.messages)
      || body.messages.length === 0) {
    gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
  }
  for (const message of body.messages) {
    if (!plainJsonObject(message)
        || !Object.hasOwn(message, 'role')
        || !GATEWAY_MESSAGE_ROLES.has(message.role)
        || !Object.hasOwn(message, 'content')) {
      gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
    }
    const allowedKeys = new Set(['content', 'name', 'role']);
    if (message.role === 'assistant') allowedKeys.add('tool_calls');
    if (message.role === 'tool') allowedKeys.add('tool_call_id');
    if (!hasOnlyKeys(message, allowedKeys)
        || (Object.hasOwn(message, 'name')
          && !boundedString(message.name, MAX_GATEWAY_PARTICIPANT_NAME_CHARACTERS))) {
      gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
    }
    const assistantToolCalls = message.role === 'assistant'
      ? supportedAssistantToolCalls(message)
      : null;
    const contentIsSupported = supportedMessageContent(message.content)
      || (message.role === 'assistant' && message.content === null && assistantToolCalls === true);
    if (!contentIsSupported
        || assistantToolCalls === false
        || (message.role === 'tool'
          && (!Object.hasOwn(message, 'tool_call_id')
            || !boundedString(message.tool_call_id, MAX_GATEWAY_TOOL_CALL_ID_CHARACTERS)))) {
      gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
    }
  }
}

function assertGatewayTools(body) {
  if (!Object.hasOwn(body, 'tools')) return;
  if (!Array.isArray(body.tools)) {
    gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
  }
  for (const tool of body.tools) {
    if (!plainJsonObject(tool)
        || !hasOnlyKeys(tool, new Set(['function', 'type']))
        || tool.type !== 'function'
        || !Object.hasOwn(tool, 'function')
        || !plainJsonObject(tool.function)
        || !hasOnlyKeys(tool.function, new Set(['description', 'name', 'parameters', 'strict']))
        || !Object.hasOwn(tool.function, 'name')
        || typeof tool.function.name !== 'string'
        || !GATEWAY_FUNCTION_NAME.test(tool.function.name)
        || (Object.hasOwn(tool.function, 'description')
          && typeof tool.function.description !== 'string')
        || (Object.hasOwn(tool.function, 'parameters')
          && !plainJsonObject(tool.function.parameters))
        || (Object.hasOwn(tool.function, 'strict')
          && typeof tool.function.strict !== 'boolean')) {
      gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
    }
  }
}

function finiteNumberInRange(value, minimum, maximum) {
  return typeof value === 'number'
    && Number.isFinite(value)
    && value >= minimum
    && value <= maximum;
}

function supportedStop(value) {
  if (typeof value === 'string') return value.length > 0;
  return Array.isArray(value)
    && value.length > 0
    && value.length <= 4
    && value.every((stop) => typeof stop === 'string' && stop.length > 0);
}

function supportedResponseFormat(value) {
  if (!plainJsonObject(value) || typeof value.type !== 'string') return false;
  if (value.type === 'text' || value.type === 'json_object') {
    return hasOnlyKeys(value, new Set(['type']));
  }
  if (value.type !== 'json_schema'
      || !hasOnlyKeys(value, new Set(['json_schema', 'type']))
      || !plainJsonObject(value.json_schema)
      || !hasOnlyKeys(value.json_schema, new Set(['description', 'name', 'schema', 'strict']))
      || !GATEWAY_FUNCTION_NAME.test(value.json_schema.name ?? '')
      || !Object.hasOwn(value.json_schema, 'schema')
      || !plainJsonObject(value.json_schema.schema)
      || (Object.hasOwn(value.json_schema, 'description')
        && typeof value.json_schema.description !== 'string')
      || (Object.hasOwn(value.json_schema, 'strict')
        && typeof value.json_schema.strict !== 'boolean')) {
    return false;
  }
  return true;
}

function supportedToolChoice(body) {
  if (!Object.hasOwn(body, 'tool_choice')) return true;
  const choice = body.tool_choice;
  if (typeof choice === 'string') {
    if (!new Set(['auto', 'none', 'required']).has(choice)) return false;
    return choice !== 'required' || body.tools?.length > 0;
  }
  if (!plainJsonObject(choice)
      || !hasOnlyKeys(choice, new Set(['function', 'type']))
      || choice.type !== 'function'
      || !plainJsonObject(choice.function)
      || !hasOnlyKeys(choice.function, new Set(['name']))
      || !GATEWAY_FUNCTION_NAME.test(choice.function.name ?? '')) {
    return false;
  }
  return body.tools?.some((tool) => tool.function.name === choice.function.name) === true;
}

function anthropicToolArgumentsAreObjects(body) {
  for (const message of body.messages) {
    for (const toolCall of message.tool_calls ?? []) {
      let parsed;
      try { parsed = JSON.parse(toolCall.function.arguments); } catch { return false; }
      if (!plainJsonObject(parsed)) return false;
    }
  }
  return true;
}

function assertGatewayProviderOptions(body, provider) {
  if (!hasOnlyKeys(body, GATEWAY_REQUEST_KEYS)
      || (Object.hasOwn(body, 'stream') && typeof body.stream !== 'boolean')
      || (Object.hasOwn(body, 'temperature')
        && (provider !== 'openai' || !finiteNumberInRange(body.temperature, 0, 2)))
      || (Object.hasOwn(body, 'top_p')
        && (provider !== 'openai' || !finiteNumberInRange(body.top_p, 0, 1)))
      || (Object.hasOwn(body, 'stop') && !supportedStop(body.stop))
      || !supportedToolChoice(body)
      || (provider === 'anthropic'
        && Object.hasOwn(body, 'tool_choice')
        && body.tool_choice !== 'none'
        && !(body.tools?.length > 0))
      || (provider === 'anthropic' && !anthropicToolArgumentsAreObjects(body))
      || (provider === 'anthropic' && toAnthropicMessages(body.messages).length === 0)
      || (Object.hasOwn(body, 'presence_penalty')
        && (provider !== 'openai' || !finiteNumberInRange(body.presence_penalty, -2, 2)))
      || (Object.hasOwn(body, 'frequency_penalty')
        && (provider !== 'openai' || !finiteNumberInRange(body.frequency_penalty, -2, 2)))
      || (Object.hasOwn(body, 'response_format')
        && (provider !== 'openai' || !supportedResponseFormat(body.response_format)))
      || (Object.hasOwn(body, 'seed')
        && (provider !== 'openai' || !Number.isSafeInteger(body.seed)))
      || (Object.hasOwn(body, 'user')
        && (provider !== 'openai' || !boundedString(body.user, 256)))
      || (provider === 'anthropic'
        && body.tools?.some((tool) => Object.hasOwn(tool.function, 'strict')))) {
    gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
  }
}

function priceForProvider(provider) {
  if (provider === 'anthropic') return MODEL_PRICES_USDC.claude;
  if (provider === 'openai') return MODEL_PRICES_USDC.gpt;
  gatewayFailure('MODEL_NOT_ALLOWED', 'gateway model is not allowed', 400);
}

function frozenCatalog(value) {
  const snapshot = structuredClone(value);
  catalogDigest(snapshot);
  for (const policy of Object.values(snapshot.models)) {
    if (!LIVE_PROVIDERS.has(policy.provider)) {
      throw new TypeError('gateway catalog provider must be anthropic or openai');
    }
  }
  return deepFreeze(snapshot);
}

function configuredLiveApproval(value) {
  if (value !== undefined) return value;
  return process.env.GATEWAY_LIVE_CATALOG_DIGEST && process.env.GATEWAY_LIVE_SPEND_CAP_ATOMIC
    ? {
      catalogDigest: process.env.GATEWAY_LIVE_CATALOG_DIGEST,
      spendCapAtomic: process.env.GATEWAY_LIVE_SPEND_CAP_ATOMIC,
    }
    : null;
}

function configuredProviderKeys(value) {
  if (value !== undefined) return structuredClone(value);
  return {
    anthropic: process.env.ANTHROPIC_API_KEY ?? null,
    openai: process.env.OPENAI_API_KEY ?? null,
  };
}

function assertLiveGatewayApproval({ catalog, approval }) {
  let maximumWorstCaseCost = 0n;
  for (const [model, policy] of Object.entries(catalog.models)) {
    const cost = usageCostAtomic({
      schemaVersion: 2,
      model,
      inputTokens: policy.maxInputTokens,
      outputTokens: policy.maxOutputTokens,
    }, catalog);
    if (cost > maximumWorstCaseCost) maximumWorstCaseCost = cost;
  }
  return assertLiveCatalogApproval({
    catalog,
    approval,
    grossAtomic: maximumWorstCaseCost.toString(),
  });
}

function createProviderSpendBudget(catalog, approvedBoundary) {
  const cap = BigInt(approvedBoundary.spendCapAtomic);
  let committed = 0n;
  let reserved = 0n;

  const worstCaseCost = (plan) => usageCostAtomic({
    schemaVersion: 2,
    model: plan.model,
    inputTokens: plan.policy.maxInputTokens,
    outputTokens: plan.maxOutputTokens,
  }, catalog);

  const availableReservation = (plan) => {
    const amount = worstCaseCost(plan);
    if (committed + reserved + amount > cap) {
      gatewayFailure(
        'PROVIDER_SPEND_CAP',
        'live provider spend budget cannot cover this request',
        503,
      );
    }
    return amount;
  };

  return {
    assertAvailable(plan) {
      availableReservation(plan);
    },
    reserve(plan) {
      const amount = availableReservation(plan);
      reserved += amount;
      let state = 'reserved';
      return {
        commit(usage) {
          if (state !== 'reserved') return;
          const actual = usageCostAtomic({
            schemaVersion: 2,
            model: plan.model,
            inputTokens: usage.prompt_tokens,
            outputTokens: usage.completion_tokens,
          }, catalog);
          if (actual > amount) {
            gatewayFailure(
              'UPSTREAM_PROVIDER_USAGE',
              'upstream provider usage is invalid',
              502,
            );
          }
          reserved -= amount;
          committed += actual;
          state = 'committed';
        },
        holdWorstCase() {
          if (state !== 'reserved') return;
          reserved -= amount;
          committed += amount;
          state = 'held';
        },
        releaseBeforeFetch() {
          if (state !== 'reserved') return;
          reserved -= amount;
          state = 'released';
        },
      };
    },
  };
}

function requestPlan(c, catalog) {
  const cached = c.get('gatewayRequestPlan');
  if (cached) return cached;
  const body = gatewayRequestBody(c);
  if (!plainJsonObject(body)) {
    gatewayFailure('REQUEST_SCHEMA', 'gateway request is invalid', 400);
  }
  if (typeof body.model !== 'string' || !Object.hasOwn(catalog.models, body.model)) {
    gatewayFailure('MODEL_NOT_ALLOWED', 'gateway model is not allowed', 400);
  }
  assertGatewayMessages(body);
  assertGatewayTools(body);
  const policy = catalog.models[body.model];
  assertGatewayProviderOptions(body, policy.provider);
  const hasLegacyLimit = Object.hasOwn(body, 'max_tokens');
  const hasCurrentLimit = Object.hasOwn(body, 'max_completion_tokens');
  if (hasLegacyLimit && hasCurrentLimit) {
    gatewayFailure('TOKEN_LIMIT', 'gateway request must provide only one output-token limit', 400);
  }
  const requestedOutputTokens = hasLegacyLimit
    ? body.max_tokens
    : hasCurrentLimit ? body.max_completion_tokens : Math.min(2_048, policy.maxOutputTokens);
  if (!Number.isSafeInteger(requestedOutputTokens)
      || requestedOutputTokens <= 0
      || requestedOutputTokens > policy.maxOutputTokens) {
    gatewayFailure('TOKEN_LIMIT', 'gateway output-token limit exceeds the catalog policy', 400);
  }
  const requestBodyBytes = x402RequestBodyBytes(c).byteLength;
  const conservativeInputTokenBound = requestBodyBytes
    + GATEWAY_PROVIDER_FRAMING_TOKEN_ALLOWANCE;
  if (conservativeInputTokenBound > policy.maxInputTokens) {
    gatewayFailure(
      'PROMPT_TOKEN_BOUND',
      'gateway request plus provider framing exceeds the conservative catalog input-token bound',
      400,
    );
  }
  const plan = deepFreeze({
    body,
    model: body.model,
    provider: policy.provider,
    policy,
    maxOutputTokens: requestedOutputTokens,
    requestBodyBytes,
    conservativeInputTokenBound,
  });
  c.set('gatewayRequestPlan', plan);
  return plan;
}

function gatewayRequestBody(c) {
  const cached = c.get('gatewayRequestBody');
  if (cached !== undefined) return cached;
  let body;
  try { body = JSON.parse(x402RequestBodyText(c)); } catch { body = null; }
  c.set('gatewayRequestBody', body);
  return body;
}

export function createGateway({
  facilitatorTransport,
  payTo = process.env.PAY_TO_ADDRESS || '0x000000000000000000000000000000000000dEaD',
  mockLlm = process.env.MOCK_LLM !== '0',
  allowLiveProvider = process.env.ALLOW_LIVE_PROVIDER === '1',
  providerCatalog = GATEWAY_EXECUTION_CATALOG,
  liveApproval = undefined,
  providerFetch = fetch,
  providerApiKeys = undefined,
  providerTimeoutMs = DEFAULT_GATEWAY_PROVIDER_TIMEOUT_MS,
  maxProviderResponseBytes = MAX_GATEWAY_PROVIDER_RESPONSE_BYTES,
} = {}) {
  positiveLimit(providerTimeoutMs, 'providerTimeoutMs');
  positiveLimit(maxProviderResponseBytes, 'maxProviderResponseBytes');
  if (providerTimeoutMs > DEFAULT_GATEWAY_PROVIDER_TIMEOUT_MS) {
    throw new RangeError(`providerTimeoutMs must not exceed ${DEFAULT_GATEWAY_PROVIDER_TIMEOUT_MS} milliseconds`);
  }
  if (maxProviderResponseBytes > MAX_GATEWAY_PROVIDER_RESPONSE_BYTES) {
    throw new RangeError('maxProviderResponseBytes must not exceed one MiB');
  }
  const catalog = frozenCatalog(providerCatalog);
  const keys = configuredProviderKeys(providerApiKeys);
  let approvedLiveBoundary = null;
  if (!mockLlm) {
    if (allowLiveProvider !== true) {
      throw new Error('live gateway execution requires an explicit live provider gate');
    }
    if (facilitatorTransport?.mode !== 'live') {
      throw new Error('live provider execution requires live x402 settlement');
    }
    if (typeof providerFetch !== 'function') throw new TypeError('gateway providerFetch must be a function');
    approvedLiveBoundary = assertLiveGatewayApproval({
      catalog,
      approval: configuredLiveApproval(liveApproval),
    });
    for (const provider of new Set(Object.values(catalog.models).map((policy) => policy.provider))) {
      if (typeof keys?.[provider] !== 'string' || keys[provider].length === 0) {
        throw new Error(`live gateway requires an injected ${provider} provider key`);
      }
    }
  }
  const providerSpendBudget = approvedLiveBoundary
    ? createProviderSpendBudget(catalog, approvedLiveBoundary)
    : null;
  const providerSpendClaims = new Map();
  const releaseProviderSpendClaim = (idempotencyKey) => {
    const claim = providerSpendClaims.get(idempotencyKey);
    if (!claim) return;
    if (claim.state === 'reserved') claim.reservation.releaseBeforeFetch();
    providerSpendClaims.delete(idempotencyKey);
  };
  const providerPaymentLifecycle = providerSpendBudget ? {
    async beforeSettlement({ context, idempotencyKey }) {
      if (providerSpendClaims.has(idempotencyKey)) {
        gatewayFailure(
          'PROVIDER_ATTEMPT_IN_PROGRESS',
          'a provider attempt already owns this payment authorization',
          503,
        );
      }
      const plan = requestPlan(context, catalog);
      const reservation = providerSpendBudget.reserve(plan);
      providerSpendClaims.set(idempotencyKey, { plan, reservation, state: 'reserved' });
    },
    async onRejected({ idempotencyKey }) {
      releaseProviderSpendClaim(idempotencyKey);
    },
    async onUnresolved({ idempotencyKey }) {
      releaseProviderSpendClaim(idempotencyKey);
    },
  } : {};
  const app = new Hono();
  app.onError((error, c) => {
    const failure = publicGatewayFailure(error);
    return c.json({ error: failure.message, code: failure.code }, failure.status);
  });
  app.get('/healthz', (c) => c.json({ ok: true, prices: MODEL_PRICES_USDC }));

  app.post(
    '/v1/chat/completions',
    x402Paywall({
      // The x402 boundary owns one bounded stream read. Pricing and execution
      // parse its cached text instead of consuming the request twice.
      price: async (c) => {
        const plan = requestPlan(c, catalog);
        providerSpendBudget?.assertAvailable(plan);
        return priceForProvider(plan.provider);
      },
      payTo,
      facilitatorTransport,
      lifecycle: providerPaymentLifecycle,
      description: 'per-call model inference (x402 reseller, testnet)',
      maxRequestBodyBytes: MAX_GATEWAY_REQUEST_BODY_BYTES,
    }),
    async (c) => {
      const plan = requestPlan(c, catalog);
      const body = plan.body;
      let completion;
      if (mockLlm) {
        completion = mockCompletion(body);
      } else {
        const x402State = c.get('x402');
        const claim = providerSpendClaims.get(x402State?.idempotencyKey);
        if (!claim || claim.state !== 'reserved' || claim.plan.model !== plan.model) {
          if (x402State?.idempotencyKey) releaseProviderSpendClaim(x402State.idempotencyKey);
          gatewayFailure(
            'PROVIDER_RESERVATION_MISSING',
            'provider spend authorization is unavailable after settlement',
            503,
          );
        }
        claim.state = 'executing';
        try {
          completion = await executeLiveProvider(plan, {
            fetchImpl: providerFetch,
            apiKey: keys[plan.provider],
            signal: c.req.raw.signal,
            timeoutMs: providerTimeoutMs,
            maxResponseBytes: maxProviderResponseBytes,
          });
          claim.reservation.commit(completion.usage);
        } catch (error) {
          claim.reservation.holdWorstCase();
          throw error;
        } finally {
          providerSpendClaims.delete(x402State.idempotencyKey);
        }
      }
      if (!body.stream) return c.json(completion);
      // OpenAI-style clients (pi included) speak SSE. The spike computes the
      // full completion first, then replays it as one compliant stream:
      // role+content delta -> finish chunk -> [DONE].
      return c.newResponse(sseFromCompletion(completion), 200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
      });
    },
  );

  return app;
}

// --- MOCK_LLM=1: canned OpenAI-format completions --------------------------
function mockCompletion(body) {
  const lastUser = contentToText([...(body.messages ?? [])].reverse().find((m) => m.role === 'user')?.content);
  const family = (body.model ?? '').startsWith('claude') ? 'claude' : 'gpt';
  const content =
    family === 'claude'
      ? `[mock ${body.model}] PLAN:\n1. Read the failing module.\n2. Sketch the fix.\n3. Hand off to implementation.\n(for: "${String(lastUser).slice(0, 80)}")`
      : `[mock ${body.model}] IMPLEMENTATION:\n\`\`\`js\n// minimal change implementing the plan\n\`\`\`\n(for: "${String(lastUser).slice(0, 80)}")`;
  return {
    id: `chatcmpl-mock-${Date.now()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: body.model,
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 42, completion_tokens: 42, total_tokens: 84 },
  };
}

// --- real upstreams ---------------------------------------------------------
// OpenAI-chat -> Anthropic Messages translation. Covers the shapes pi actually
// sends: content as a string OR an array of typed parts, tool definitions,
// assistant tool_calls, and role:"tool" results.
const contentToText = (content) =>
  typeof content === 'string' ? content
  : Array.isArray(content) ? content.map((p) => (typeof p === 'string' ? p : p?.text ?? '')).join('')
  : content == null ? '' : String(content);

function toAnthropicMessages(oaiMessages = []) {
  const out = [];
  const push = (role, blocks) => {
    if (!blocks.length) return;
    const prev = out[out.length - 1];
    // Anthropic requires alternating roles; tool results (user) can directly
    // follow a real user turn, so merge consecutive same-role turns.
    if (prev && prev.role === role) prev.content.push(...blocks);
    else out.push({ role, content: [...blocks] });
  };
  for (const m of oaiMessages) {
    if (GATEWAY_SYSTEM_MESSAGE_ROLES.has(m.role)) continue;
    if (m.role === 'tool') {
      push('user', [{ type: 'tool_result', tool_use_id: m.tool_call_id, content: contentToText(m.content) }]);
    } else if (m.role === 'assistant') {
      const blocks = [];
      const text = contentToText(m.content);
      if (text) blocks.push({ type: 'text', text });
      for (const tc of m.tool_calls ?? []) {
        blocks.push({ type: 'tool_use', id: tc.id, name: tc.function.name, input: JSON.parse(tc.function.arguments || '{}') });
      }
      push('assistant', blocks);
    } else {
      push('user', [{ type: 'text', text: contentToText(m.content) }]);
    }
  }
  return out;
}

function publicGatewayFailure(error) {
  if (error instanceof GatewayBoundaryError) {
    return { code: error.code, message: error.message, status: error.status };
  }
  if (error instanceof RuntimeBoundaryError) {
    const failures = {
      UPSTREAM_PROVIDER_TIMEOUT: {
        message: 'upstream provider timed out', status: 504,
      },
      UPSTREAM_PROVIDER_ABORTED: {
        message: 'upstream provider was aborted', status: 504,
      },
      UPSTREAM_PROVIDER_RESPONSE_TOO_LARGE: {
        message: 'upstream provider response exceeds the byte limit', status: 502,
      },
      UPSTREAM_PROVIDER_RESPONSE_READ_FAILED: {
        message: 'upstream provider response is invalid', status: 502,
      },
      UPSTREAM_PROVIDER_RESPONSE_JSON: {
        message: 'upstream provider response is invalid', status: 502,
      },
    };
    const known = failures[error.code];
    if (known) return { code: error.code, ...known };
  }
  return {
    code: 'UPSTREAM_PROVIDER_ERROR',
    message: 'upstream provider request failed',
    status: 502,
  };
}

function providerReadOptions(maxResponseBytes, signal) {
  return {
    maxBytes: maxResponseBytes,
    tooLargeCode: 'UPSTREAM_PROVIDER_RESPONSE_TOO_LARGE',
    tooLargeMessage: 'upstream provider response exceeds the JSON byte limit',
    readErrorCode: 'UPSTREAM_PROVIDER_RESPONSE_READ_FAILED',
    readErrorMessage: 'upstream provider response could not be read',
    jsonErrorCode: 'UPSTREAM_PROVIDER_RESPONSE_JSON',
    jsonErrorMessage: 'upstream provider response was not JSON',
    signal,
  };
}

function validateProviderUsage(plan, inputTokens, outputTokens) {
  if (!Number.isSafeInteger(inputTokens) || inputTokens < 0
      || !Number.isSafeInteger(outputTokens) || outputTokens < 0
      || inputTokens > plan.policy.maxInputTokens
      || outputTokens > plan.maxOutputTokens) {
    gatewayFailure('UPSTREAM_PROVIDER_USAGE', 'upstream provider usage is invalid', 502);
  }
  return { inputTokens, outputTokens };
}

function anthropicRequest(plan, apiKey) {
  const body = plan.body;
  const system = (body.messages ?? [])
    .filter((message) => GATEWAY_SYSTEM_MESSAGE_ROLES.has(message.role))
    .map((message) => contentToText(message.content))
    .join('\n') || undefined;
  const tools = (body.tools ?? []).map((t) => ({
    name: t.function.name,
    description: t.function.description ?? '',
    input_schema: t.function.parameters ?? { type: 'object', properties: {} },
  }));
  const toolChoice = !Object.hasOwn(body, 'tool_choice') || body.tool_choice === 'none'
    ? null
    : body.tool_choice === 'required'
      ? { type: 'any' }
      : body.tool_choice === 'auto'
        ? { type: 'auto' }
        : { type: 'tool', name: body.tool_choice.function.name };
  const stopSequences = !Object.hasOwn(body, 'stop')
    ? null
    : typeof body.stop === 'string' ? [body.stop] : body.stop;
  return {
    url: 'https://api.anthropic.com/v1/messages',
    init: {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: plan.model,
        max_tokens: plan.maxOutputTokens,
        ...(stopSequences ? { stop_sequences: stopSequences } : {}),
        system,
        messages: toAnthropicMessages(body.messages),
        ...(tools.length && body.tool_choice !== 'none' ? { tools } : {}),
        ...(toolChoice ? { tool_choice: toolChoice } : {}),
      }),
    },
  };
}

function openAiRequest(plan, apiKey) {
  const body = plan.body;
  const allowedFields = [
    'messages', 'tools', 'tool_choice', 'temperature', 'top_p', 'stop',
    'presence_penalty', 'frequency_penalty', 'response_format', 'seed', 'user',
  ];
  const forwarded = Object.fromEntries(allowedFields
    .filter((field) => Object.hasOwn(body, field))
    .map((field) => [field, body[field]]));
  forwarded.messages = body.messages.map((message) => ({
    ...message,
    ...(Array.isArray(message.content)
      ? { content: message.content.map((part) => ({ type: 'text', text: part.text })) }
      : {}),
  }));
  return {
    url: 'https://api.openai.com/v1/chat/completions',
    init: {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        ...forwarded,
        model: plan.model,
        max_completion_tokens: plan.maxOutputTokens,
        n: 1,
        stream: false,
      }),
    },
  };
}

function providerRequest(plan, apiKey) {
  return plan.provider === 'anthropic'
    ? anthropicRequest(plan, apiKey)
    : openAiRequest(plan, apiKey);
}

function anthropicCompletion(plan, data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)
      || !Array.isArray(data.content) || !data.usage || typeof data.usage !== 'object') {
    gatewayFailure('UPSTREAM_PROVIDER_RESPONSE_SCHEMA', 'upstream provider response is invalid', 502);
  }
  const usage = validateProviderUsage(
    plan,
    data.usage.input_tokens,
    data.usage.output_tokens,
  );
  const text = data.content.filter((block) => block?.type === 'text')
    .map((block) => (typeof block.text === 'string' ? block.text : ''))
    .join('');
  const toolCalls = data.content.filter((block) => block?.type === 'tool_use').map((block) => ({
    id: block.id,
    type: 'function',
    function: { name: block.name, arguments: JSON.stringify(block.input ?? {}) },
  }));
  return {
    id: data.id,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: data.model,
    choices: [{
      index: 0,
      message: {
        role: 'assistant',
        content: toolCalls.length && !text ? null : text,
        ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
      },
      finish_reason: data.stop_reason === 'tool_use' ? 'tool_calls'
        : data.stop_reason === 'max_tokens' ? 'length' : 'stop',
    }],
    usage: {
      prompt_tokens: usage.inputTokens,
      completion_tokens: usage.outputTokens,
      total_tokens: usage.inputTokens + usage.outputTokens,
    },
  };
}

function openAiCompletion(plan, data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)
      || !Array.isArray(data.choices) || data.choices.length === 0
      || !data.usage || typeof data.usage !== 'object') {
    gatewayFailure('UPSTREAM_PROVIDER_RESPONSE_SCHEMA', 'upstream provider response is invalid', 502);
  }
  validateProviderUsage(
    plan,
    data.usage.prompt_tokens,
    data.usage.completion_tokens,
  );
  return data;
}

async function executeLiveProvider(plan, {
  fetchImpl,
  apiKey,
  signal,
  timeoutMs,
  maxResponseBytes,
}) {
  try {
    return await withWallClockDeadline({
      signal,
      timeoutMs,
      timeoutCode: 'UPSTREAM_PROVIDER_TIMEOUT',
      timeoutMessage: 'upstream provider timed out',
      abortedCode: 'UPSTREAM_PROVIDER_ABORTED',
      abortedMessage: 'upstream provider was aborted',
    }, async (composedSignal) => {
      const request = providerRequest(plan, apiKey);
      const response = await fetchImpl(request.url, {
        ...request.init,
        redirect: 'error',
        signal: composedSignal,
      });
      if (!response?.ok) {
        try {
          Promise.resolve(response?.body?.cancel?.()).catch(() => {});
        } catch { /* the sanitized HTTP failure owns the result */ }
        gatewayFailure('UPSTREAM_PROVIDER_HTTP', 'upstream provider request failed', 502);
      }
      const data = await readJsonBody(
        response,
        providerReadOptions(maxResponseBytes, composedSignal),
      );
      return plan.provider === 'anthropic'
        ? anthropicCompletion(plan, data)
        : openAiCompletion(plan, data);
    });
  } catch (error) {
    if (error instanceof GatewayBoundaryError || error instanceof RuntimeBoundaryError) throw error;
    gatewayFailure('UPSTREAM_PROVIDER_ERROR', 'upstream provider request failed', 502);
  }
}

/** Boot helper shared by the standalone script and e2e.mjs. */
export function startGateway({ port = 0, ...opts } = {}) {
  const app = createGateway(opts);
  return new Promise((resolve) => {
    const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' }, (info) => {
      let closePromise = null;
      const close = () => {
        closePromise ??= new Promise((closeResolve, closeReject) => {
          server.close((error) => (error ? closeReject(error) : closeResolve()));
        });
        return closePromise;
      };
      resolve({
        url: `http://127.0.0.1:${info.port}`,
        port: info.port,
        address: info.address,
        close,
      });
    });
  });
}

// Standalone: `npm run gateway`
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let facilitatorTransport;
  let facilitatorMode;
  if (process.env.ALLOW_LIVE_X402 === '1') {
    facilitatorTransport = createLiveFacilitatorTransport(process.env.FACILITATOR_URL);
    facilitatorMode = 'approved-base-sepolia';
  } else {
    const { createMockFacilitator } = await import('./facilitator-mock.mjs');
    const facilitator = createMockFacilitator();
    facilitatorTransport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
    facilitatorMode = 'in-process-mock';
  }
  const { url } = await startGateway({
    port: Number(process.env.GATEWAY_PORT || 8403),
    facilitatorTransport,
  });
  console.log(`[gateway] x402-gated /v1/chat/completions at ${url} (facilitator: ${facilitatorMode})`);
}

// Wrap a completed chat.completion as OpenAI SSE chunks. Not true streaming —
// the whole answer arrives in one delta — but protocol-correct for clients
// that refuse buffered JSON ("Stream ended without finish_reason").
function sseFromCompletion(completion) {
  const base = { id: completion.id, object: 'chat.completion.chunk', created: completion.created, model: completion.model };
  const msg = completion.choices[0].message;
  const d = { role: 'assistant' };
  if (msg.content) d.content = msg.content;
  if (msg.tool_calls?.length) d.tool_calls = msg.tool_calls.map((tc, index) => ({ index, ...tc }));
  const delta = { ...base, choices: [{ index: 0, delta: d, finish_reason: null }] };
  const finish = { ...base, choices: [{ index: 0, delta: {}, finish_reason: completion.choices[0].finish_reason ?? 'stop' }], usage: completion.usage ?? null };
  return `data: ${JSON.stringify(delta)}\n\ndata: ${JSON.stringify(finish)}\n\ndata: [DONE]\n\n`;
}

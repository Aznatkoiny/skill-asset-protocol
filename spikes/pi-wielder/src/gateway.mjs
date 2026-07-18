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
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
  x402Paywall,
} from './x402-seller.mjs';

// Flat per-call testnet prices by model family (real resellers price per
// token; per-call keeps the 402 requirements computable before inference).
export const MODEL_PRICES_USDC = Object.freeze({ claude: '0.041', gpt: '0.087', default: '0.05' });
const priceFor = (model = '') =>
  model.startsWith('claude') ? MODEL_PRICES_USDC.claude
  : model.startsWith('gpt') ? MODEL_PRICES_USDC.gpt
  : MODEL_PRICES_USDC.default;

export function createGateway({
  facilitatorTransport,
  payTo = process.env.PAY_TO_ADDRESS || '0x000000000000000000000000000000000000dEaD',
  mockLlm = process.env.MOCK_LLM === '1',
} = {}) {
  const app = new Hono();
  app.get('/healthz', (c) => c.json({ ok: true, prices: MODEL_PRICES_USDC }));

  app.post(
    '/v1/chat/completions',
    x402Paywall({
      // Per-request pricing: Hono caches the parsed body, so reading it here
      // and again in the handler is safe.
      price: async (c) => priceFor((await c.req.json().catch(() => ({}))).model),
      payTo,
      facilitatorTransport,
      description: 'per-call model inference (x402 reseller, testnet)',
    }),
    async (c) => {
      const body = await c.req.json();
      const model = body.model ?? '';
      const completion = mockLlm ? mockCompletion(body)
        : model.startsWith('claude') ? await viaAnthropic(body)
        : await viaOpenAI(body); // gpt-* and anything else
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
    if (m.role === 'system') continue;
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

async function viaAnthropic(body) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY required for claude-* models unless MOCK_LLM=1');
  const system = (body.messages ?? []).filter((m) => m.role === 'system').map((m) => contentToText(m.content)).join('\n') || undefined;
  const tools = (body.tools ?? []).map((t) => ({
    name: t.function.name,
    description: t.function.description ?? '',
    input_schema: t.function.parameters ?? { type: 'object', properties: {} },
  }));
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({
      model: body.model,
      max_tokens: body.max_tokens ?? 2048,
      system,
      messages: toAnthropicMessages(body.messages),
      ...(tools.length ? { tools } : {}),
    }),
  });
  if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  const text = data.content?.filter((b) => b.type === 'text').map((b) => b.text).join('') ?? '';
  const toolCalls = (data.content ?? []).filter((b) => b.type === 'tool_use').map((b) => ({
    id: b.id, type: 'function', function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) },
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
      prompt_tokens: data.usage?.input_tokens ?? 0,
      completion_tokens: data.usage?.output_tokens ?? 0,
      total_tokens: (data.usage?.input_tokens ?? 0) + (data.usage?.output_tokens ?? 0),
    },
  };
}

async function viaOpenAI(body) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error('OPENAI_API_KEY required for gpt-* models unless MOCK_LLM=1');
  // Always fetch buffered — the gateway synthesizes its own SSE downstream.
  const { stream, stream_options, max_tokens, ...rest } = body;
  // Newer OpenAI models reject max_tokens (400 unsupported_parameter) and
  // require max_completion_tokens; clients (pi included) send max_tokens.
  if (max_tokens != null && rest.max_completion_tokens == null) rest.max_completion_tokens = max_tokens;
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify(rest),
  });
  if (!res.ok) throw new Error(`OpenAI API ${res.status}: ${await res.text()}`);
  return res.json();
}

/** Boot helper shared by the standalone script and e2e.mjs. */
export function startGateway({ port = 0, ...opts } = {}) {
  const app = createGateway(opts);
  return new Promise((resolve) => {
    const server = serve({ fetch: app.fetch, port }, (info) => {
      resolve({ url: `http://127.0.0.1:${info.port}`, port: info.port, close: () => server.close() });
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

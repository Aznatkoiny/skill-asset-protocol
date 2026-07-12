// collar.mjs — the mock Collar: the single trusted component on the seller side.
//
// The Collar is the sole platform-key holder, the x402 resource server, and
// the off-chain meter for ONE hosted Skill: this repo's own
// `.claude/skills/optimizing-claude-code-prompts`. Its contract:
//
//   * The skill CONTENT never leaves this process. The Wielder pays for an
//     INVOCATION and receives OUTPUT ONLY — artifact scarcity is preserved by
//     hosting (ADR-0001), and the x402-settled txHash is the single-use
//     execution credential ("no credential, no run", ADR-0003).
//   * Every settled invocation is metered into the prototype settlement
//     engine (prototype/settlement-engine.mjs), which computes the royalty
//     split (creator 100% here) net of the 2.5% protocol fee. The engine is
//     the accounting mirror of the on-chain USDC payment: value arrives once
//     via EIP-3009, the engine attributes it.
//
// The engine's public economic event is `invoke()` (pay -> mint credential ->
// consume -> settle); its internal `distribute()` does the recursive royalty
// flow-through. `distribute` is not exported, so we drive it through
// `invoke()` and use the returned breakdown — same math, public API.
//
// Engine amounts are kept in ATOMIC USDC (6-decimal integers) because the
// engine rounds to 2 decimals — fine for dollars, lossy for $0.25 micro-
// royalties. 0.25 USDC = 250_000 atomic -> fee 6_250, creator 243_750, exact.

import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { x402Paywall, atomicToUsdc, usdcToAtomic } from './x402-seller.mjs';
import {
  createState, addParty, registerSkill, setRoyalty, invoke,
} from '../../../prototype/settlement-engine.mjs';

export const SKILL_ID = 'optimizing-claude-code-prompts';
const SKILL_PATH = fileURLToPath(
  new URL(`../../../.claude/skills/${SKILL_ID}/SKILL.md`, import.meta.url),
);
const DEFAULT_PRICE_USDC = 0.25;

export function createCollar({
  facilitatorUrl,
  payTo = process.env.PAY_TO_ADDRESS || '0x000000000000000000000000000000000000dEaD',
  priceUsdc = Number(process.env.SKILL_PRICE_USDC || DEFAULT_PRICE_USDC),
  mockLlm = process.env.MOCK_LLM === '1',
} = {}) {
  // The platform key: the skill content, loaded once, never serialized out.
  const skillContent = fs.readFileSync(SKILL_PATH, 'utf8');

  // --- the off-chain meter: settlement-engine state for this one skill -----
  const state = createState(); // feeBps: 250 (2.5% protocol fee)
  addParty(state, { id: 'creator', name: 'Skill creator', role: 'Creator' });
  // The engine debits the wielder's balance as the mirror of the on-chain
  // USDC transfer; seed it deep enough for any session.
  addParty(state, { id: 'wielder', name: 'Session wallet', role: 'Wielder/Beneficiary', balance: 1e12 });
  registerSkill(state, { id: SKILL_ID, name: SKILL_ID, creatorId: 'creator', price: Number(usdcToAtomic(priceUsdc)), mode: 'marketplace' });
  setRoyalty(state, SKILL_ID, [{ partyId: 'creator', bps: 10000 }]); // creator holds 100%

  const app = new Hono();
  app.get('/healthz', (c) => c.json({ ok: true, skill: SKILL_ID, priceUsdc }));

  app.post(
    '/invoke/:skillId',
    x402Paywall({ price: priceUsdc, payTo, facilitatorUrl, description: `hosted-skill invocation: ${SKILL_ID}` }),
    async (c) => {
      if (c.req.param('skillId') !== SKILL_ID) return c.json({ error: `unknown skill '${c.req.param('skillId')}'` }, 404);
      const { input } = await c.req.json().catch(() => ({}));
      if (!input) return c.json({ error: 'body must be JSON: { "input": "..." }' }, 400);
      const payment = c.get('x402'); // { txHash, payer, amountUsdc } from the paywall

      // Execute the skill: SKILL.md is the system prompt, the buyer's input is
      // the user turn. Output only ever flows out.
      const output = mockLlm ? mockSkillOutput(input) : await runSkillViaAnthropic(skillContent, input);

      // Meter the settled invocation. invoke() re-runs pay -> credential ->
      // distribute() inside the engine and returns the royalty breakdown.
      const result = invoke(state, SKILL_ID, 'wielder');
      const splits = [
        ...result.breakdown.map((b) => ({ party: b.partyId, amountUSDC: atomicToUsdc(b.amount) })),
        { party: 'treasury', amountUSDC: atomicToUsdc(result.fee) },
      ];

      return c.json({
        output, // and ONLY the output — never skillContent
        receipt: { skillId: SKILL_ID, txHash: payment.txHash, payer: payment.payer, amountUSDC: payment.amountUsdc, splits },
      });
    },
  );

  return app;
}

// Canned skill output for MOCK_LLM=1: recognizably an *optimized prompt*,
// recognizably NOT the skill's own text.
function mockSkillOutput(input) {
  return [
    `[mock ${SKILL_ID}] Optimized prompt for: "${String(input).slice(0, 120)}"`,
    '',
    'Goal: <grounded restatement of the request>',
    'Context: <where this lives in the repo>',
    'Constraints: <what must not change>',
    'Done when: <a real, runnable check>',
  ].join('\n');
}

async function runSkillViaAnthropic(skillContent, input) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY required unless MOCK_LLM=1');
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 2048,
      system: skillContent, // the platform key stays server-side
      messages: [{ role: 'user', content: String(input) }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.content?.map((b) => b.text ?? '').join('') ?? '';
}

/** Boot helper shared by the standalone script and e2e.mjs. */
export function startCollar({ port = 0, ...opts } = {}) {
  const app = createCollar(opts);
  return new Promise((resolve) => {
    const server = serve({ fetch: app.fetch, port }, (info) => {
      resolve({ url: `http://127.0.0.1:${info.port}`, port: info.port, close: () => server.close() });
    });
  });
}

// Standalone: `npm run collar`
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { startMockFacilitator } = await import('./facilitator-mock.mjs');
  const facilitatorUrl = process.env.MOCK_FACILITATOR === '1'
    ? (await startMockFacilitator()).url
    : (process.env.FACILITATOR_URL || 'https://x402.org/facilitator');
  const { url } = await startCollar({ port: Number(process.env.COLLAR_PORT || 8404), facilitatorUrl });
  console.log(`[collar] hosted skill '${SKILL_ID}' at ${url}/invoke/${SKILL_ID} (facilitator: ${facilitatorUrl})`);
}

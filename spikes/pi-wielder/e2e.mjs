// e2e.mjs — the proof: ONE WALLET, TWO ASSET CLASSES, ONE ATTRIBUTED LEDGER.
//
// Fully offline under MOCK_FACILITATOR=1 + MOCK_LLM=1 (the default when run
// as `npm run e2e`): no network, no API keys, no funds. It boots the collar,
// the inference gateway, and the Wielder proxy on ephemeral ports, then —
// through THE PROXY ONLY — makes a claude "plan" completion, a gpt
// "implement" completion, and one hosted-skill invocation, asserting the
// whole x402 + settlement story along the way.

process.env.MOCK_FACILITATOR ??= '1';
process.env.MOCK_LLM ??= '1';

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { startMockFacilitator } from './src/facilitator-mock.mjs';
import { startCollar, SKILL_ID } from './src/collar.mjs';
import { startGateway, MODEL_PRICES_USDC } from './src/gateway.mjs';
import { startProxy } from './src/proxy.mjs';
import { throwawayAccount } from './src/wallet.mjs';
import { usdcToAtomic, atomicToUsdc } from './src/x402-seller.mjs';
import {
  createState, addParty, registerSkill, setRoyalty, invoke,
} from '../../prototype/settlement-engine.mjs';

// --- tiny assertion harness --------------------------------------------------
let checks = 0;
function ok(cond, label) {
  checks += 1;
  if (!cond) { console.error(`  ✗ ${label}`); process.exitCode = 1; throw new Error(`FAILED: ${label}`); }
  console.log(`  ✓ ${label}`);
}
const eq = (a, b, label) => ok(JSON.stringify(a) === JSON.stringify(b), `${label} (${JSON.stringify(a)} === ${JSON.stringify(b)})`);

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const LEDGER_FILE = here('./session-ledger.jsonl');
fs.rmSync(LEDGER_FILE, { force: true });

// --- boot: facilitator -> sellers -> the one wallet's paying proxy ------------
const account = throwawayAccount(); // zero funds needed: mock facilitator verifies signatures, fakes settlement
const facilitator = await startMockFacilitator();
const collar = await startCollar({ facilitatorUrl: facilitator.url });
const gateway = await startGateway({ facilitatorUrl: facilitator.url });
const proxy = await startProxy({ account, gatewayUrl: gateway.url, collarUrl: collar.url, ledgerFile: LEDGER_FILE });

console.log(`\nPi-Wielder e2e (MOCK_FACILITATOR=${process.env.MOCK_FACILITATOR}, MOCK_LLM=${process.env.MOCK_LLM})`);
console.log(`wallet ${account.address}`);
console.log(`facilitator ${facilitator.url} · collar ${collar.url} · gateway ${gateway.url} · proxy ${proxy.url}\n`);

const overheads = [];
async function viaProxy(path, body, label) {
  const res = await fetch(`${proxy.url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(label ? { 'x-session-label': label } : {}) },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  const timings = res.headers.get('x-wielder-overhead');
  if (timings) overheads.push({ call: label ?? path, ...JSON.parse(timings) });
  return { res, json };
}

try {
  // --- 0. the gates are real: unpaid direct requests are refused --------------
  console.log('unpaid requests are 402-challenged:');
  for (const [name, url] of [['gateway', `${gateway.url}/v1/chat/completions`], ['collar', `${collar.url}/invoke/${SKILL_ID}`]]) {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'gpt-x', input: 'x' }) });
    const b = await r.json();
    ok(r.status === 402 && b.x402Version === 1 && b.accepts?.[0]?.scheme === 'exact', `${name} answers 402 with an "exact" payment offer`);
  }

  // --- 1. asset class one: per-call model inference (claude plans...) ---------
  console.log('\nleg 1 — model inference, claude/plan:');
  const plan = await viaProxy('/v1/chat/completions', {
    model: 'claude-sonnet-4-6',
    messages: [{ role: 'user', content: 'Plan a refactor of the settlement engine tests.' }],
  }, 'plan');
  ok(plan.res.status === 200, 'completion succeeded through the proxy');
  ok(plan.res.headers.get('x-wielder-402') === '1', 'proxy hit a 402 first and paid to proceed');
  ok(plan.json.choices?.[0]?.message?.content?.length > 0, 'got assistant content back');

  // --- 2. ...and gpt implements — same wallet, different upstream -------------
  console.log('\nleg 2 — model inference, gpt/implement:');
  const impl = await viaProxy('/v1/chat/completions', {
    model: 'gpt-5.2',
    messages: [{ role: 'user', content: 'Implement the plan.' }],
  }, 'implement');
  ok(impl.res.status === 200, 'completion succeeded through the proxy');
  ok(impl.res.headers.get('x-wielder-402') === '1', 'proxy hit a 402 first and paid to proceed');

  // --- 3. asset class two: hosted-skill invocation behind the collar ----------
  console.log(`\nleg 3 — hosted skill, ${SKILL_ID}:`);
  const skill = await viaProxy(`/invoke/${SKILL_ID}`, { input: 'make the checkout page faster' });
  ok(skill.res.status === 200, 'invocation succeeded through the proxy');
  ok(skill.res.headers.get('x-wielder-402') === '1', 'proxy hit a 402 first and paid to proceed');
  ok(skill.json.output?.length > 0, 'skill returned output');

  // Output only — the skill's content must never cross the collar boundary.
  const skillMd = fs.readFileSync(here(`../../.claude/skills/${SKILL_ID}/SKILL.md`), 'utf8');
  const fullResponse = JSON.stringify(skill.json);
  const fingerprints = ['The one rule that makes this skill worth invoking', 'The seven ingredients', skillMd.slice(0, 400)];
  ok(fingerprints.every((f) => !fullResponse.includes(f)), 'response contains NO skill content (checked 3 fingerprints)');

  // --- 4. the settled txHash is a single-use credential: replay refused -------
  console.log('\nreplay protection:');
  const usedPayment = skill.res.headers.get('x-wielder-payment');
  const replay = await fetch(`${collar.url}/invoke/${SKILL_ID}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'X-PAYMENT': usedPayment },
    body: JSON.stringify({ input: 'try to run again on the same payment' }),
  });
  ok(replay.status === 409, `replaying the settled credential is rejected (HTTP ${replay.status})`);
  ok((await replay.json()).error?.includes('replay'), 'rejection names the replay');

  // --- 5. the unified ledger: 3 entries, exact engine-computed skill split ----
  console.log('\nunified session ledger:');
  const entries = await (await fetch(`${proxy.url}/ledger?format=json`)).json();
  eq(entries.length, 3, 'ledger has exactly 3 entries');
  eq(entries.map((e) => e.leg), ['model', 'model', 'skill'], 'legs attributed: model, model, skill');
  eq(entries.map((e) => e.label), ['claude/plan', 'gpt/implement', `skill/${SKILL_ID}`], 'labels attributed');
  eq(entries.map((e) => e.amountUSDC), [MODEL_PRICES_USDC.claude, MODEL_PRICES_USDC.gpt, 0.25], 'amounts match the quoted 402 offers');
  ok(entries.every((e) => /^0x[0-9a-f]{64}$/.test(e.txHash)), 'every entry carries a settlement txHash');

  // Recompute the skill split with the settlement engine itself (same seed
  // shapes the collar uses) and demand an exact match. distribute() is not
  // exported by the prototype, so we drive it through the public invoke().
  const ref = createState();
  addParty(ref, { id: 'creator', name: 'Skill creator', role: 'Creator' });
  addParty(ref, { id: 'wielder', name: 'Session wallet', role: 'Wielder/Beneficiary', balance: 1e12 });
  registerSkill(ref, { id: SKILL_ID, name: SKILL_ID, creatorId: 'creator', price: Number(usdcToAtomic(0.25)), mode: 'marketplace' });
  setRoyalty(ref, SKILL_ID, [{ partyId: 'creator', bps: 10000 }]);
  const expected = invoke(ref, SKILL_ID, 'wielder');
  const expectedSplits = [
    ...expected.breakdown.map((b) => ({ party: b.partyId, amountUSDC: atomicToUsdc(b.amount) })),
    { party: 'treasury', amountUSDC: atomicToUsdc(expected.fee) },
  ];
  eq(entries[2].splits, expectedSplits, 'skill split matches settlement-engine distribute() exactly');
  eq(entries[2].splits, skill.json.receipt.splits, 'collar receipt and ledger agree');

  // --- 6. payment overhead (MOCK numbers) --------------------------------------
  console.log('\nper-call x402 payment overhead — MOCK numbers (localhost, fake settlement;');
  console.log('testnet adds real facilitator HTTP + Base Sepolia inclusion time):');
  for (const o of overheads) {
    console.log(`  ${o.call.padEnd(10)} 402-roundtrip ${o.ms402.toFixed(1)}ms · sign ${o.msSign.toFixed(1)}ms · verify+settle ${o.msFacilitator.toFixed(1)}ms · total overhead ${o.msOverhead.toFixed(1)}ms`);
  }
  const sorted = overheads.map((o) => o.msOverhead).sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length / 2)];
  console.log(`  p50 ${p50.toFixed(1)}ms · max ${sorted.at(-1).toFixed(1)}ms (n=${sorted.length}, mock)`);

  // --- the money shot -----------------------------------------------------------
  console.log('\nsession ledger (one wallet, two asset classes, three payees):');
  console.log('  ' + (await (await fetch(`${proxy.url}/ledger`)).text()).split('\n').join('\n  '));
  console.log(`  (JSONL at ${LEDGER_FILE})`);

  console.log(`\nPASS — ${checks} checks green.`);
} finally {
  proxy.close(); gateway.close(); collar.close(); facilitator.close();
}

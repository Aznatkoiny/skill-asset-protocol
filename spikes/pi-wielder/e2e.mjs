// Offline proof: one Wielder wallet, model payments plus a Skill Invocation,
// and one local receipt view. Every HTTP hop is an in-process Hono request;
// no listener, network route, funded wallet, or live facilitator is used.

process.env.MOCK_LLM = '1';

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import { createCollar, SKILL_ID } from './src/collar.mjs';
import { createMockFacilitator } from './src/facilitator-mock.mjs';
import { createGateway, MODEL_PRICES_USDC } from './src/gateway.mjs';
import { verifySignedReceipt } from './src/invocation-journal.mjs';
import { createDefaultPaymentPolicy, payingFetch, createProxy } from './src/proxy.mjs';
import { throwawayAccount } from './src/wallet.mjs';
import { createMockFacilitatorTransport, usdcToAtomic } from './src/x402-seller.mjs';

let checks = 0;
function ok(condition, label) {
  checks += 1;
  if (!condition) throw new Error(`FAILED: ${label}`);
  console.log(`  ✓ ${label}`);
}
const eq = (actual, expected, label) => ok(
  JSON.stringify(actual) === JSON.stringify(expected),
  `${label} (${JSON.stringify(actual)} === ${JSON.stringify(expected)})`,
);
const here = (relative) => fileURLToPath(new URL(relative, import.meta.url));

const account = throwawayAccount();
const facilitator = createMockFacilitator();
const facilitatorTransport = createMockFacilitatorTransport(
  (url, init) => facilitator.request(url, init),
);
const collar = createCollar({
  facilitatorTransport,
  mockLlm: true,
  journalFile: null,
  signingKeyFile: null,
});
const gateway = createGateway({ facilitatorTransport, mockLlm: true });
const proxy = createProxy({
  account,
  gatewayUrl: 'http://gateway.test',
  collarUrl: 'http://collar.test',
  gatewayFetch: (url, init) => gateway.request(url, init),
  collarFetch: (url, init) => collar.app.request(url, init),
  ledgerFile: null,
  trustedCollarPublicKeyPem: collar.journal.signingPublicKeyPem,
  trustedCollarKeyId: collar.journal.signingKeyId,
});
const trust = {
  publicKeyPem: collar.journal.signingPublicKeyPem,
  keyId: collar.journal.signingKeyId,
};

console.log('\nPi-Wielder offline in-process e2e');
console.log(`wallet ${account.address} (throwaway, unfunded)`);

const overheads = [];
async function viaProxy(path, body, label = null) {
  const res = await proxy.app.request(`http://proxy.test${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(label ? { 'x-session-label': label } : {}),
    },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  const timings = res.headers.get('x-wielder-overhead');
  if (timings) overheads.push({ call: label ?? path, ...JSON.parse(timings) });
  return { res, json };
}

console.log('unpaid requests are challenged:');
for (const [name, app, url, body] of [
  ['gateway', gateway, 'http://gateway.test/v1/chat/completions', { model: 'gpt-x' }],
  ['collar', collar.app, `http://collar.test/invoke/${SKILL_ID}`, { input: 'x' }],
]) {
  const response = await app.request(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Idempotency-Key': `unpaid-${name}`,
    },
    body: JSON.stringify(body),
  });
  const challenge = await response.json();
  ok(
    response.status === 402
      && challenge.x402Version === 1
      && challenge.accepts?.[0]?.scheme === 'exact',
    `${name} returns one exact x402 offer`,
  );
}

console.log('\nmodel receipt views:');
const plan = await viaProxy('/v1/chat/completions', {
  model: 'claude-sonnet-4-6',
  messages: [{ role: 'user', content: 'Plan a refactor.' }],
}, 'plan');
ok(plan.res.status === 200, 'claude model leg settles and succeeds');
ok(plan.json.choices?.[0]?.message?.content?.length > 0, 'claude mock output returned');
const implementation = await viaProxy('/v1/chat/completions', {
  model: 'gpt-5.2',
  messages: [{ role: 'user', content: 'Implement the plan.' }],
}, 'implement');
ok(implementation.res.status === 200, 'gpt model leg settles and succeeds');

console.log('\nSkill receipt authority:');
const skillRequestBody = JSON.stringify({ input: 'make the checkout page faster' });
const skill = await viaProxy(`/invoke/${SKILL_ID}`, JSON.parse(skillRequestBody));
ok(skill.res.status === 200, 'Skill Invocation settles and succeeds');
ok(skill.json.output?.length > 0, 'Skill output returned');
ok(verifySignedReceipt(skill.json.receipt, trust), 'response receipt verifies against pinned Collar key');
const skillContent = fs.readFileSync(here(`../../.claude/skills/${SKILL_ID}/SKILL.md`), 'utf8');
const responseBytes = JSON.stringify(skill.json);
ok([
  'The one rule that makes this skill worth invoking',
  'The seven ingredients',
  skillContent.slice(0, 400),
].every((fingerprint) => !responseBytes.includes(fingerprint)), 'mock response omits tested direct Skill artifact fingerprints and bytes');

const entries = proxy.ledger.entries;
eq(entries.length, 3, 'Wielder view has three settled calls');
eq(entries.map((entry) => entry.leg), ['model', 'model', 'skill'], 'both asset classes are attributed');
ok(entries.every((entry) => entry.view === 'wielder-receipt'), 'every local entry identifies itself as a receipt view');
ok(entries.every((entry) => entry.status === 'succeeded'), 'successful terminal state is retained');
eq(entries.map((entry) => entry.amountAtomic), [
  usdcToAtomic(MODEL_PRICES_USDC.claude),
  usdcToAtomic(MODEL_PRICES_USDC.gpt),
  usdcToAtomic('0.25'),
], 'quoted amounts remain canonical atomic strings');
ok(entries.every((entry) => /^0x[0-9a-f]{64}$/.test(entry.txHash)), 'every settled view carries a transaction hash');
const policySnapshot = proxy.paymentPolicy.snapshot();
eq(policySnapshot.spentAtomic, usdcToAtomic('0.378'), 'policy records exact session spend');
eq(policySnapshot.reservedAtomic, '0', 'no successful authorization remains reserved');
eq(policySnapshot.authorizations.length, 3, 'one authorization exists per paid call');
ok(policySnapshot.authorizations.every((authorization) => authorization.retryCount === 1), 'every authorization retried exactly once');
ok(policySnapshot.authorizations.every((authorization) => authorization.state === 'settled'), 'every e2e authorization settled');
ok(
  JSON.stringify(entries[2].receipt) === JSON.stringify(skill.json.receipt),
  'response and Wielder cache contain the identical signed receipt',
);
const authoritative = collar.journal.getByTxHash(entries[2].txHash);
eq(entries[2].receipt.receipt.invocationId, authoritative.invocationId, 'receipt view points to the authoritative Collar Invocation');
const accounting = entries[2].receipt.receipt.accounting;
eq(entries[2].splits, [
  ...accounting.holderCredits.map((credit) => ({
    party: credit.recipientId,
    amountAtomic: credit.amountAtomic,
  })),
  ...accounting.ancestorCredits.map((credit) => ({
    party: credit.recipientId,
    amountAtomic: credit.amountAtomic,
  })),
  { party: 'treasury', amountAtomic: accounting.protocolFeeAtomic },
], 'displayed claims are projected only from finalized signed accounting');

console.log('\nidempotency and replay:');
const skillEntry = entries[2];
const usedPayment = skill.res.headers.get('x-wielder-payment');
const eventCount = collar.journal.events.length;
const exactReplay = await collar.app.request(`http://collar.test/invoke/${SKILL_ID}`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'Idempotency-Key': skillEntry.idempotencyKey,
    'X-PAYMENT': usedPayment,
  },
  body: skillRequestBody,
});
ok(exactReplay.status === 200 && (await exactReplay.json()).replayed === true, 'exact paid retry replays terminal receipt');
eq(collar.journal.events.length, eventCount, 'terminal replay appends no event and executes no Skill');
const conflict = await collar.app.request(`http://collar.test/invoke/${SKILL_ID}`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'Idempotency-Key': skillEntry.idempotencyKey,
    'X-PAYMENT': usedPayment,
  },
  body: JSON.stringify({ input: 'different bytes' }),
});
ok(conflict.status === 409, 'conflicting body under the same key fails before execution');

console.log('\nunresolved settlement:');
const lossyFacilitator = createMockFacilitator();
let settleCalls = 0;
const lossyTransport = createMockFacilitatorTransport(async (url, init) => {
  const response = await lossyFacilitator.request(url, init);
  if (new URL(url).pathname === '/settle') {
    settleCalls += 1;
    throw new Error('synthetic response loss');
  }
  return response;
});
const unresolvedCollar = createCollar({
  facilitatorTransport: lossyTransport,
  mockLlm: true,
  journalFile: null,
  signingKeyFile: null,
});
const unresolvedKey = 'e2e-unresolved-payment';
const unresolvedUrl = `http://unresolved.test/invoke/${SKILL_ID}`;
const unresolvedPolicy = createDefaultPaymentPolicy({
  gatewayUrl: 'http://unresolved.test',
  collarUrl: 'http://unresolved.test',
  env: {},
});
let unresolvedError = null;
try {
  await payingFetch(account, unresolvedUrl, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: skillRequestBody,
  }, {
    idempotencyKey: unresolvedKey,
    fetchImpl: (url, init) => unresolvedCollar.app.request(url, init),
    paymentPolicy: unresolvedPolicy,
  });
} catch (error) {
  unresolvedError = error;
}
ok(
  unresolvedError?.code === 'SETTLEMENT_EVIDENCE'
    && !('res' in unresolvedError),
  'lost settlement response withholds output and is explicitly unresolved',
);
const unresolved = unresolvedPolicy.recoverSignedAuthorization({
  authorizationId: unresolvedKey,
  requestUrl: unresolvedUrl,
  method: 'POST',
  bodyBytes: skillRequestBody,
});
ok(
  unresolvedPolicy.snapshot().authorizations[0].state === 'unresolved'
    && unresolvedPolicy.snapshot().reservedAtomic === '250000',
  'unknown settlement keeps the exact session budget reservation',
);
const unresolvedRetry = await unresolvedCollar.app.request(`http://unresolved.test/invoke/${SKILL_ID}`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'Idempotency-Key': unresolvedKey,
    'X-PAYMENT': unresolved.xPayment,
  },
  body: skillRequestBody,
});
ok(unresolvedRetry.status === 503, 'exact unresolved retry remains blocked for trusted reconciliation');
eq(settleCalls, 1, 'unresolved retry never re-verifies or re-settles');

console.log('\nWielder receipt view:');
console.log(`  ${(await (await proxy.app.request('http://proxy.test/ledger')).text()).split('\n').join('\n  ')}`);
console.log('\nSynthetic in-process payment overhead (not network measurements):');
for (const sample of overheads) {
  console.log(`  ${sample.call}: ${sample.msOverhead.toFixed(1)}ms synthetic`);
}
console.log(`\nPASS — ${checks} checks green (offline, in-process, synthetic timings).`);

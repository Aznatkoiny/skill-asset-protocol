// spike-fork-economics.mjs
//
// PRE-BUILD SPIKE (run: node prototype/spike-fork-economics.mjs)
// Questions: what inherit-bps keeps forking worthwhile; what happens to the
// ORIGINAL Creator as Derivative chains deepen; and does any school-paying
// inherit survive a free, no-lineage re-author alternative?

import assert from 'node:assert/strict';

import * as E from './settlement-engine.mjs';

const FEE_BPS = 250;
const ROOT_PRICE = 5;
const UPLIFT = 10;
const CANDIDATE_PRICE = ROOT_PRICE + UPLIFT;
const INITIAL_WIELDER_BALANCE = 1_000;
const BASELINE = Object.freeze({
  reauthorCostPerInvocationCents: 0,
  creatorCapturedLineageValueCents: 0,
});

let invariantCount = 0;
function equal(actual, expected, message) {
  invariantCount += 1;
  assert.equal(actual, expected, message);
}
function deepEqual(actual, expected, message) {
  invariantCount += 1;
  assert.deepEqual(actual, expected, message);
}
function ok(value, message) {
  invariantCount += 1;
  assert.ok(value, message);
}

const cents = (dollars) => Math.round(Number(dollars) * 100);
const money = (valueCents) => E.money(valueCents / 100);
const pct = (value, total) => `${(value / total * 100).toFixed(1)}%`;
const historicalFreshUpliftAlt = UPLIFT * (1 - FEE_BPS / 10_000);

// Historical A/B model: the outside option values only the fresh $10 uplift.
function runHistorical(depth, inheritBps) {
  const state = E.createState();
  E.setFee(state, FEE_BPS);
  E.addParty(state, { id: 'w', name: 'W', role: 'Wielder', balance: 1e9 });
  for (let k = 0; k <= depth; k += 1) {
    E.addParty(state, { id: `c${k}`, name: `c${k}`, role: 'Creator' });
  }
  E.registerSkill(state, { id: 's0', name: 's0', creatorId: 'c0', price: ROOT_PRICE });
  let price = ROOT_PRICE;
  for (let k = 1; k <= depth; k += 1) {
    price += UPLIFT;
    E.forkSkill(state, {
      id: `s${k}`,
      parentId: `s${k - 1}`,
      creatorId: `c${k}`,
      name: `s${k}`,
      price,
      inheritBps,
    });
  }
  const result = E.invoke(state, `s${depth}`, 'w');
  const got = {};
  for (const item of result.breakdown) {
    got[item.partyId] = (got[item.partyId] || 0) + item.amount;
  }
  return { price: result.price, net: result.net, got };
}

function payoutCents(result, partyId) {
  return result.breakdown
    .filter((item) => item.partyId === partyId)
    .reduce((sum, item) => sum + cents(item.amount), 0);
}

function runEducationBranch({ kind, inheritBps = 0, candidatePrice = CANDIDATE_PRICE }) {
  const state = E.createState();
  E.setFee(state, FEE_BPS);
  E.addParty(state, { id: 'school', name: 'School', role: 'Creator' });
  E.addParty(state, { id: 'student', name: 'Student-Creator', role: 'Creator' });
  E.addParty(state, {
    id: 'employer',
    name: 'Employer',
    role: 'Wielder/Beneficiary',
    balance: INITIAL_WIELDER_BALANCE,
  });
  E.registerSkill(state, {
    id: 'school-base',
    name: 'school-base',
    creatorId: 'school',
    price: ROOT_PRICE,
    mode: 'education',
  });

  const skillId = kind === 'declared' ? 'declared-derivative' : 'reauthored-root';
  if (kind === 'declared') {
    E.forkSkill(state, {
      id: skillId,
      parentId: 'school-base',
      creatorId: 'student',
      name: skillId,
      price: candidatePrice,
      inheritBps,
    });
  } else if (kind === 'reauthored') {
    E.registerSkill(state, {
      id: skillId,
      name: skillId,
      creatorId: 'student',
      price: candidatePrice,
      mode: 'education',
    });
  } else {
    throw new Error(`unknown Education branch kind: ${kind}`);
  }

  const result = E.invoke(state, skillId, 'employer');
  return {
    ancestry: E.ancestry(state, skillId),
    schoolBreakdownCount: result.breakdown.filter((item) => item.partyId === 'school').length,
    feeBps: state.feeBps,
    priceCents: cents(result.price),
    feeCents: cents(result.fee),
    netCents: cents(result.net),
    schoolPayoutCents: payoutCents(result, 'school'),
    creatorPayoutCents: payoutCents(result, 'student'),
    schoolBalanceCents: cents(state.parties.school.balance),
    creatorBalanceCents: cents(state.parties.student.balance),
    wielderSpendCents: cents(INITIAL_WIELDER_BALANCE - state.parties.employer.balance),
    treasuryCents: cents(state.treasury),
  };
}

function classifyDeclaredChoice(
  declared,
  reauthored,
  {
    reauthorCostPerInvocationCents = BASELINE.reauthorCostPerInvocationCents,
    creatorCapturedLineageValueCents = BASELINE.creatorCapturedLineageValueCents,
  } = {},
) {
  const netParityCents = declared.netCents - reauthored.netCents;
  const availableAdvantageCents = (
    netParityCents
    + reauthorCostPerInvocationCents
    + creatorCapturedLineageValueCents
  );
  const classification = declared.schoolPayoutCents < availableAdvantageCents
    ? 'declared-strictly-preferred'
    : declared.schoolPayoutCents === availableAdvantageCents
      ? 'tie'
      : 'reauthor-strictly-preferred';
  return { netParityCents, classification };
}

const reauthored = runEducationBranch({ kind: 'reauthored' });
deepEqual(reauthored.ancestry, [], 're-authored Skill is a no-lineage root');
equal(reauthored.schoolBreakdownCount, 0, 'school is absent from re-author breakdown');
equal(reauthored.schoolPayoutCents, 0, 'school receives no re-author payout');
equal(reauthored.schoolBalanceCents, 0, 'school balance does not change on re-author Invocation');
equal(reauthored.feeBps, FEE_BPS, 're-author branch explicitly sets the 2.5% fee');
equal(reauthored.priceCents, 1_500, 're-author candidate price is $15');
equal(reauthored.feeCents, 38, '2.5% fee rounds to $0.38 at $15');
equal(reauthored.netCents, 1_462, 'post-fee net is $14.62 at $15');
equal(reauthored.creatorPayoutCents, 1_462, 'student-Creator receives full re-author net');
equal(reauthored.creatorBalanceCents, 1_462, 'student-Creator balance matches payout');
equal(reauthored.wielderSpendCents, 1_500, 'Wielder spends the exact Invocation price');
equal(reauthored.treasuryCents, 38, 'treasury receives the exact fee');
equal(reauthored.feeCents + reauthored.netCents, reauthored.priceCents, 're-author fee plus net conserves price');
equal(reauthored.creatorPayoutCents, reauthored.netCents, 're-author payout conserves net');

// Stream every integer bps to answer the literal "any positive rate" question,
// but retain only the 1%-grid economics and a separate local rounding probe.
const economicRates = new Set([0, ...Array.from({ length: 100 }, (_, index) => (index + 1) * 100)]);
const roundingProbeRates = new Set([1, 2, 3, 4]);
const economicRows = new Map();
const roundingRows = new Map();
let integerRatesChecked = 0;
let positivePayingRates = 0;
let allBranchShapesMatch = true;
let allAccountingConserves = true;
let allPositivePayingRatesLose = true;

for (let inheritBps = 0; inheritBps <= 10_000; inheritBps += 1) {
  const declared = runEducationBranch({ kind: 'declared', inheritBps });
  const comparison = classifyDeclaredChoice(declared, reauthored);
  const row = { inheritBps, ...declared, ...comparison };
  integerRatesChecked += 1;
  if (declared.schoolPayoutCents > 0) positivePayingRates += 1;
  allBranchShapesMatch &&= (
    declared.ancestry.length === 1
    && declared.ancestry[0] === 'school-base'
    && declared.feeBps === FEE_BPS
    && declared.priceCents === reauthored.priceCents
    && declared.netCents === reauthored.netCents
    && comparison.netParityCents === 0
  );
  allAccountingConserves &&= (
    declared.feeCents + declared.netCents === declared.priceCents
    && declared.creatorPayoutCents + declared.schoolPayoutCents === declared.netCents
    && declared.creatorBalanceCents === declared.creatorPayoutCents
    && declared.schoolBalanceCents === declared.schoolPayoutCents
    && declared.wielderSpendCents === declared.priceCents
    && declared.treasuryCents === declared.feeCents
  );
  if (declared.schoolPayoutCents > 0) {
    allPositivePayingRatesLose &&= comparison.classification === 'reauthor-strictly-preferred';
  }
  if (economicRates.has(inheritBps)) economicRows.set(inheritBps, row);
  if (roundingProbeRates.has(inheritBps)) roundingRows.set(inheritBps, row);
}

equal(integerRatesChecked, 10_001, 'stream checks every integer rate from 0 through 10000 bps');
equal(positivePayingRates, 9_997, 'integer stream finds school payouts from 4 through 10000 bps');
ok(allBranchShapesMatch, 'all streamed declared branches hold fee, price, net, and ancestry at parity');
ok(allAccountingConserves, 'all streamed branches conserve integer-cent fees and payouts');
ok(allPositivePayingRatesLose, 'every streamed school-paying rate loses at V=$0');
equal(economicRows.size, 101, 'economic grid contains 0 plus every integer percentage');

const zeroBps = economicRows.get(0);
equal(zeroBps.schoolPayoutCents, 0, '0 bps sends the school $0');
equal(zeroBps.classification, 'tie', '0 bps ties the free re-author branch');
const positiveEconomicRows = [...economicRows.values()].filter((row) => row.inheritBps > 0);
ok(positiveEconomicRows.every((row) => row.schoolPayoutCents > 0), 'every 1%-grid positive rate pays the school');
ok(
  positiveEconomicRows.every((row) => row.classification === 'reauthor-strictly-preferred'),
  'every 1%-grid positive rate loses at V=$0',
);

for (const inheritBps of [1, 2, 3]) {
  const row = roundingRows.get(inheritBps);
  equal(row.schoolPayoutCents, 0, `${inheritBps} bps local probe rounds school payout to $0`);
  equal(row.classification, 'tie', `${inheritBps} bps local probe ties only because payout rounds to $0`);
  equal(row.schoolBreakdownCount, 1, `${inheritBps} bps local probe traverses lineage`);
}
const fourBps = roundingRows.get(4);
equal(fourBps.schoolPayoutCents, 1, '4 bps local probe is the first $0.01 school payout');
equal(fourBps.classification, 'reauthor-strictly-preferred', '4 bps loses when re-author cost is $0');
equal(
  classifyDeclaredChoice(fourBps, reauthored, { reauthorCostPerInvocationCents: 1 }).classification,
  'tie',
  '4 bps ties when re-authoring costs $0.01 per Invocation',
);
equal(
  classifyDeclaredChoice(fourBps, reauthored, { reauthorCostPerInvocationCents: 2 }).classification,
  'declared-strictly-preferred',
  '4 bps strictly wins when re-authoring costs $0.02 per Invocation',
);

const optionThresholds = [
  { inheritBps: 100, expectedCents: 15 },
  { inheritBps: 500, expectedCents: 73 },
  { inheritBps: 1_000, expectedCents: 146 },
  { inheritBps: 2_000, expectedCents: 292 },
  { inheritBps: 3_000, expectedCents: 439 },
].map(({ inheritBps, expectedCents }) => {
  const row = economicRows.get(inheritBps);
  equal(row.schoolPayoutCents, expectedCents, `${inheritBps} bps exact ancestor payout`);
  equal(
    classifyDeclaredChoice(row, reauthored, {
      creatorCapturedLineageValueCents: expectedCents,
    }).classification,
    'tie',
    `${inheritBps} bps ties when Creator-captured V equals ancestor payout`,
  );
  equal(
    classifyDeclaredChoice(row, reauthored, {
      creatorCapturedLineageValueCents: expectedCents - 1,
    }).classification,
    'reauthor-strictly-preferred',
    `${inheritBps} bps loses when Creator-captured V is one cent short`,
  );
  equal(
    classifyDeclaredChoice(row, reauthored, {
      creatorCapturedLineageValueCents: expectedCents + 1,
    }).classification,
    'declared-strictly-preferred',
    `${inheritBps} bps wins when Creator-captured V is one cent above payout`,
  );
  return { inheritBps, requiredValueCents: expectedCents };
});

const seededTuiDeclared = runEducationBranch({ kind: 'declared', inheritBps: 3_000, candidatePrice: 25 });
const seededTuiReauthored = runEducationBranch({ kind: 'reauthored', candidatePrice: 25 });
equal(seededTuiDeclared.feeCents, 63, 'seeded TUI analog fee is $0.63');
equal(seededTuiDeclared.netCents, 2_437, 'seeded TUI analog net is $24.37');
equal(seededTuiDeclared.schoolPayoutCents, 731, 'seeded TUI 30% ancestor payout is $7.31');
equal(seededTuiDeclared.creatorPayoutCents, 1_706, 'seeded TUI Creator payout is $17.06');
equal(seededTuiDeclared.feeCents + seededTuiDeclared.netCents, 2_500, 'seeded TUI fee plus net conserves price');
equal(seededTuiDeclared.schoolPayoutCents + seededTuiDeclared.creatorPayoutCents, seededTuiDeclared.netCents, 'seeded TUI payouts conserve net');
equal(
  classifyDeclaredChoice(seededTuiDeclared, seededTuiReauthored, {
    creatorCapturedLineageValueCents: 731,
  }).classification,
  'tie',
  'seeded TUI analog needs $7.31 of Creator-captured V to tie',
);

console.log('MODEL A/B (historical): root price $5; each fork adds +$10 uplift; flat inherit per hop; fee 2.5%.');
console.log(`Historical fresh-uplift outside option (author only the $10 uplift) = $${historicalFreshUpliftAlt.toFixed(2)} per call.`);
console.log('This A/B outside option is not the Education free re-author bypass.\n');

console.log('=== A. DEPTH DILUTION of the ORIGINAL Creator (root c0) ===');
for (const inheritBps of [2_000, 3_000]) {
  console.log(`\n  inherit = ${inheritBps / 100}% per hop:`);
  for (const depth of [1, 2, 3, 4]) {
    const { price, net, got } = runHistorical(depth, inheritBps);
    console.log(`   depth ${depth} ($${price}): leaf ${pct(got[`c${depth}`] || 0, net)}  | ORIGINAL ${pct(got.c0 || 0, net)}`);
  }
}

console.log('\n=== B. HISTORICAL FRESH-UPLIFT THRESHOLD (NOT THE EDUCATION BYPASS) ===');
for (const depth of [1, 2]) {
  const parentPrice = ROOT_PRICE + (depth - 1) * UPLIFT;
  const leafPrice = ROOT_PRICE + depth * UPLIFT;
  console.log(`\n  depth ${depth} (parent $${parentPrice} -> leaf $${leafPrice}): hypothesis i* = ${((parentPrice / leafPrice) * 100).toFixed(1)}%`);
  for (const inheritBps of [0, 3_000, 4_000, 5_000, 6_000, 7_000]) {
    const leaf = runHistorical(depth, inheritBps).got[`c${depth}`] || 0;
    const verdict = cents(leaf) > cents(historicalFreshUpliftAlt)
      ? 'strictly beats historical solo uplift'
      : cents(leaf) === cents(historicalFreshUpliftAlt)
        ? 'ties historical solo uplift'
        : 'loses to historical solo uplift';
    console.log(`   ${inheritBps / 100}% -> leaf keeps $${leaf.toFixed(2)}  (${verdict})`);
  }
}

console.log('\n=== C. FREE RE-AUTHOR BYPASS — DETERMINISTIC MODEL RESULT ===');
console.log('Baseline: same $15 candidate price, demand, quality, hosting cost, and inference cost; amortized re-author cost $0; Creator-captured lineage V=$0.');
console.log(`No-lineage re-authored root: ancestry []; fee ${money(reauthored.feeCents)}; student-Creator ${money(reauthored.creatorPayoutCents)}; school ${money(reauthored.schoolPayoutCents)} with no breakdown entry.`);
console.log(`Economic grid (0, then 1%..100%): 0 bps is a tie; every positive rate pays the school and makes re-authoring strictly preferable at V=$0. The 1% point pays ${money(economicRows.get(100).schoolPayoutCents)}.`);
console.log('No economically meaningful school-paying inherit survives this baseline.');
console.log('LOCAL ENGINE CENT-ROUNDING PROBE — NOT A PROTOCOL OR ECONOMIC THRESHOLD: 1–3 bps tie because the payout rounds to $0.00; 4 bps pays $0.01 and loses when re-author cost is $0.');
console.log('A streamed 0..10000 bps check confirms every school-paying integer rate loses; the full rows are not retained.');

console.log('\n=== D. LIVE-EVOLUTION OPTION VALUE — HYPOTHESIS, NOT MEASURED ===');
console.log('Survival equation: ancestor payout <= net parity + amortized re-author cost per Invocation + Creator-captured lineage-only V.');
console.log('Under this parity baseline with zero re-author cost, it reduces to: ancestor payout <= V. Equality is a tie, not strict preference.');
for (const row of optionThresholds) {
  console.log(`   ${row.inheritBps / 100}% at $15 -> exact ancestor payout ${money(row.requiredValueCents)} -> minimum Creator-captured V ${money(row.requiredValueCents)} (tie)`);
}
console.log(`   Seeded TUI analog: 30% at $25 -> net ${money(seededTuiDeclared.netCents)} -> ancestor payout / minimum V ${money(seededTuiDeclared.schoolPayoutCents)} (tie).`);
console.log('The current engine does not deliver living updates. V counts only when the Creator captures exclusive lineage value through price, demand, or avoided maintenance—not value enjoyed only by the Beneficiary.');
console.log('\nThese are deterministic engine arithmetic results, not observed student, market, or evolution behavior.');
console.log(`PASS — ${invariantCount} invariants green.`);

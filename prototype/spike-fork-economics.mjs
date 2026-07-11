// spike-fork-economics.mjs
//
// PRE-BUILD SPIKE (run: node prototype/spike-fork-economics.mjs)
// Question: what inherit-bps keeps forking worthwhile, and what happens to the
// ORIGINAL creator (the school) as derivative chains get deeper?
// Drives the design choice between Story's LRP (per-hop relative) and LAP
// (whole-ancestry absolute) royalty policies. See prototype/README.md NOTES.

import * as E from './settlement-engine.mjs';

const FEE = 250, base = 5, uplift = 10;

function run(depth, inh) {
  const s = E.createState();
  E.addParty(s, { id: 'w', name: 'W', role: 'Wielder', balance: 1e9 });
  for (let k = 0; k <= depth; k++) E.addParty(s, { id: 'c' + k, name: 'c' + k, role: 'Creator' });
  E.registerSkill(s, { id: 's0', name: 's0', creatorId: 'c0', price: base });
  let price = base;
  for (let k = 1; k <= depth; k++) { price += uplift; E.forkSkill(s, { id: 's' + k, parentId: 's' + (k - 1), creatorId: 'c' + k, name: 's' + k, price, inheritBps: inh }); }
  const r = E.invoke(s, 's' + depth, 'w');
  const got = {}; for (const b of r.breakdown) got[b.partyId] = (got[b.partyId] || 0) + b.amount;
  return { price: r.price, net: r.net, got };
}

const pct = (x, n) => (x / n * 100).toFixed(1) + '%';
const freshAlt = uplift * (1 - FEE / 10000);

console.log('MODEL: root price $5; each fork adds +$10 uplift; flat inherit per hop; fee 2.5%.');
console.log('Fresh alternative (author your $10 uplift solo) = $' + freshAlt.toFixed(2) + ' per call.\n');

console.log('=== A. DEPTH DILUTION of the ORIGINAL creator (root c0) ===');
for (const inh of [2000, 3000]) {
  console.log('\n  inherit = ' + (inh / 100) + '% per hop:');
  for (const d of [1, 2, 3, 4]) {
    const { price, net, got } = run(d, inh);
    const leaf = got['c' + d] || 0, root = got['c0'] || 0;
    console.log('   depth ' + d + ' ($' + price + '): leaf ' + pct(leaf, net) + '  | ORIGINAL ' + pct(root, net));
  }
}

console.log('\n=== B. FORK-KILLING THRESHOLD for the leaf (hypothesis i* = p_parent/p_fork) ===');
for (const d of [1, 2]) {
  const parentPrice = base + (d - 1) * uplift, leafPrice = base + d * uplift;
  console.log('\n  depth ' + d + ' (parent $' + parentPrice + ' -> leaf $' + leafPrice + '): i* = ' + ((parentPrice / leafPrice) * 100).toFixed(1) + '%');
  for (const inh of [0, 3000, 4000, 5000, 6000, 7000]) {
    const { got } = run(d, inh); const leaf = got['c' + d] || 0;
    console.log('   ' + (inh / 100) + '% -> leaf keeps $' + leaf.toFixed(2) + (leaf >= freshAlt ? '  (beats solo)' : '  NO'));
  }
}

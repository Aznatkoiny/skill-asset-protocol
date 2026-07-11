// settlement-tui.mjs
//
// PROTOTYPE — THROWAWAY terminal shell. Delete this file once the economics question
// is answered; keep settlement-engine.mjs. Run:  node prototype/settlement-tui.mjs

import readline from 'node:readline';
import * as E from './settlement-engine.mjs';

const B = (s) => `\x1b[1m${s}\x1b[0m`;
const D = (s) => `\x1b[2m${s}\x1b[0m`;
const G = (s) => `\x1b[32m${s}\x1b[0m`;
const R = (s) => `\x1b[31m${s}\x1b[0m`;
const Y = (s) => `\x1b[33m${s}\x1b[0m`;
const C = (s) => `\x1b[36m${s}\x1b[0m`;
const pad = (s, n) => String(s).padEnd(n);
const m = E.money;

const state = E.createState();
E.seedDemo(state);

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function render() {
  console.clear();
  const L = [];
  L.push(B('  SKILL ASSET PROTOCOL — settlement loop prototype'));
  L.push(D(`  protocol fee: ${(state.feeBps / 100).toFixed(2)}%   treasury: ${m(state.treasury)}   credentials minted: ${state.credentials.length}`));
  L.push('');

  // Parties
  L.push(B('  PARTIES'));
  L.push(D('  ' + pad('id', 10) + pad('name', 26) + pad('role', 22) + 'balance'));
  for (const p of Object.values(state.parties)) {
    const bal = p.balance > 0 ? G(m(p.balance)) : D(m(p.balance));
    L.push('  ' + C(pad(p.id, 10)) + pad(p.name, 26) + D(pad(p.role, 22)) + bal);
  }
  L.push('');

  // Skills
  L.push(B('  SKILLS'));
  L.push(D('  ' + pad('id', 9) + pad('name', 24) + pad('mode', 12) + pad('price', 8) + pad('ancestry / inherit', 24) + 'royalty claim'));
  for (const s of Object.values(state.skills)) {
    const anc = s.parentIds.length ? `↳ ${s.parentIds.join(',')} @ ${(s.inheritBps / 100).toFixed(0)}%↑` : D('— (root)');
    const roy = s.royalty.map((h) => `${h.partyId} ${(h.bps / 100).toFixed(0)}%`).join(' + ');
    L.push('  ' + C(pad(s.id, 9)) + pad(s.name, 24) + D(pad(s.mode, 12)) + pad(m(s.price), 8) + pad(anc, 24) + roy);
  }
  L.push('');

  // Last result
  L.push(B('  LAST ACTION'));
  const r = state.lastResult;
  if (!r) {
    L.push(D('  (none yet)'));
  } else if (r.type === 'error') {
    L.push('  ' + R('✗ ' + r.message));
  } else if (r.type === 'note') {
    L.push('  ' + Y(r.note));
  } else if (r.type === 'invoke') {
    L.push('  ' + G(`✓ ${r.wielderName} invoked ${B(r.skillName)}`) + D(`  → ${r.output}`));
    L.push(D(`    paid ${m(r.price)}  ·  credential ${r.credentialId} minted & consumed  ·  protocol fee ${m(r.fee)}  ·  net ${m(r.net)}`));
    L.push(D('    split:'));
    for (const b of r.breakdown) {
      const indent = '      ' + '  '.repeat(b.depth);
      const tag = b.kind === 'creator' ? C('creator ') : Y('↑ancestor');
      L.push(indent + tag + ' ' + pad(b.partyName, 24) + G(m(b.amount)) + D(`  via ${b.viaSkillName} (${(b.bps / 100).toFixed(0)}%)`));
    }
  }
  L.push('');

  // Commands
  L.push(B('  COMMANDS'));
  L.push(D('  invoke <skill> <wielder>     bypass <skill> <wielder>     price <skill> <amt>'));
  L.push(D('  royalty <skill> p:bps,p:bps  inherit <skill> <bps>        fee <bps>'));
  L.push(D('  fork <parent> <creator> <name> <price> <inheritBps>       skill <name> <creator> <price>'));
  L.push(D('  party <name> <role> <balance>     seed (reset)     help     quit'));
  L.push('');
  process.stdout.write(L.join('\n') + '\n');
}

function handle(line) {
  const [cmd, ...a] = line.trim().split(/\s+/).filter(Boolean);
  try {
    switch ((cmd || 'help').toLowerCase()) {
      case 'invoke': E.invoke(state, a[0], a[1]); break;
      case 'bypass': E.attemptBypass(state, a[0], a[1]); break;
      case 'price': E.setPrice(state, a[0], a[1]); state.lastResult = { type: 'note', note: `price of ${a[0]} set to ${m(a[1])}` }; break;
      case 'inherit': E.setInherit(state, a[0], a[1]); state.lastResult = { type: 'note', note: `${a[0]} now passes ${(a[1] / 100).toFixed(0)}% up to ancestors` }; break;
      case 'fee': E.setFee(state, a[0]); state.lastResult = { type: 'note', note: `protocol fee set to ${(a[0] / 100).toFixed(2)}%` }; break;
      case 'royalty': {
        const holders = a[1].split(',').map((pair) => { const [partyId, bps] = pair.split(':'); return { partyId, bps: Number(bps) }; });
        E.setRoyalty(state, a[0], holders);
        state.lastResult = { type: 'note', note: `royalty claim of ${a[0]} re-split: ${a[1]}` };
        break;
      }
      case 'fork': E.forkSkill(state, { parentId: a[0], creatorId: a[1], name: a[2], price: a[3], inheritBps: a[4] }); state.lastResult = { type: 'note', note: `forked ${a[2]} from ${a[0]}` }; break;
      case 'skill': E.registerSkill(state, { name: a[0], creatorId: a[1], price: a[2] }); state.lastResult = { type: 'note', note: `registered skill ${a[0]}` }; break;
      case 'party': E.addParty(state, { name: a[0], role: a[1], balance: a[2] }); state.lastResult = { type: 'note', note: `added party ${a[0]}` }; break;
      case 'seed': case 'reset': E.seedDemo(state); break;
      case 'help': case 'h': case '?': state.lastResult = { type: 'note', note: 'Try: invoke biofin biocorp   (education flow-through), or invoke recon otherco (co-held claim).' }; break;
      case 'quit': case 'q': case 'exit': rl.close(); return;
      default: state.lastResult = { type: 'error', message: `unknown command '${cmd}' — type help` };
    }
  } catch (err) {
    state.lastResult = { type: 'error', message: err.message };
  }
  render();
  rl.question('> ', handle);
}

render();
rl.question('> ', handle);
rl.on('close', () => { console.log('\nbye — prototype state was in-memory only.'); process.exit(0); });

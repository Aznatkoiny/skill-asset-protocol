// ledger.mjs — the unified, attributed session ledger. THE product claim.
//
// Inference calls and skill invocations are different asset classes with
// different settlement stories (pass-through vs royalty split), but they are
// entries in the SAME ledger, attributed to the SAME wallet session. That
// "unified meter" is what the design doc says differentiates this from the
// commoditizing x402 inference resellers (Router402, ClawRouter, tx402.ai).
//
// Format: JSONL, one entry per paid call:
//   { ts, leg: "model"|"skill", label, amountUSDC, txHash, splits }
//   splits: [{ party, amountUSDC }] for skill legs (royalty breakdown +
//           protocol treasury, produced by the settlement engine), null for
//           plain pass-through model legs.

import fs from 'node:fs';

export function createLedger(filePath = null) {
  const entries = [];
  return {
    entries,
    record(entry) {
      const full = { ts: new Date().toISOString(), ...entry };
      entries.push(full);
      if (filePath) fs.appendFileSync(filePath, JSON.stringify(full) + '\n');
      return full;
    },
  };
}

const fmt = (n) => '$' + Number(n).toFixed(6).replace(/0+$/, '').replace(/\.$/, '');

/**
 * One-line session view, e.g.:
 *   claude/plan $0.041 · gpt/implement $0.087 · skill/optimizing-claude-code-prompts $0.25
 *     → creator $0.24375 / treasury $0.00625
 */
export function renderLedger(entries) {
  if (!entries.length) return '(empty session ledger)';
  const parts = entries.map((e) => {
    let s = `${e.label} ${fmt(e.amountUSDC)}`;
    if (e.splits?.length) s += ` → ${e.splits.map((x) => `${x.party} ${fmt(x.amountUSDC)}`).join(' / ')}`;
    return s;
  });
  const total = entries.reduce((a, e) => a + Number(e.amountUSDC), 0);
  return `${parts.join(' · ')}\n  session total ${fmt(total)} across ${entries.length} paid calls, one wallet`;
}

// Wielder-side receipt view.
//
// The Collar journal is authoritative for Skill Invocations. This store keeps
// only what the payer observed: payment identity plus the pinned, verified
// signed Collar receipt when the leg is a Skill. It never recomputes claims.

import fs from 'node:fs';

import { formatUsdc } from '../../../prototype/atomic-money.mjs';

export function createLedger(filePath = null) {
  const entries = [];
  return {
    entries,
    record(entry) {
      if (entry.view !== 'wielder-receipt') {
        throw new Error("Wielder ledger entries must use view 'wielder-receipt'");
      }
      const full = { ts: new Date().toISOString(), ...structuredClone(entry) };
      entries.push(full);
      if (filePath) fs.appendFileSync(filePath, `${JSON.stringify(full)}\n`);
      return full;
    },
  };
}

const display = (amountAtomic) => `$${formatUsdc(BigInt(amountAtomic))
  .replace(/0+$/, '').replace(/\.$/, '')}`;

export function renderLedger(entries) {
  if (!entries.length) return '(empty Wielder receipt view)';
  const parts = entries.map((entry) => {
    let line = `${entry.label} ${display(entry.amountAtomic)} [${entry.status}]`;
    if (entry.splits?.length) {
      line += ` → ${entry.splits.map((split) => `${split.party} ${display(split.amountAtomic)}`).join(' / ')}`;
    }
    return line;
  });
  const totalAtomic = entries.reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n);
  return `${parts.join(' · ')}\n  session receipt total ${display(totalAtomic)} across ${entries.length} settled calls, one wallet`;
}

// settlement-engine.mjs
//
// PROTOTYPE — pure logic module (the keeper). No terminal I/O lives here, so this
// can be lifted into the real codebase later. The TUI shell imports it; nothing
// flows the other way.
//
// Models the Skill Asset Protocol settlement loop (see ../CONTEXT.md, ../docs/adr/):
//   register Skill -> fork into Derivatives (ancestry graph) -> Wielder pays per
//   Invocation -> single-use Execution credential minted & consumed -> payment splits
//   to royalty holders, flowing through the Derivative ancestry to ancestors, minus a
//   protocol fee.

export function createState() {
  return {
    feeBps: 250, // protocol fee, basis points (250 = 2.5%)
    treasury: 0,
    parties: {}, // id -> { id, name, role, balance }
    skills: {}, // id -> { id, name, creatorId, mode, price, parentIds:[], inheritBps, royalty:[{partyId,bps}] }
    credentials: [], // { id, skillId, wielderId, used }
    seq: 0,
    lastResult: null, // most recent action outcome, for the TUI to render
  };
}

// ---- mutations (pure w.r.t. the passed state; no side effects outside it) ----

export function addParty(state, { id, name, role, balance = 0 }) {
  id = id || slug(name);
  if (state.parties[id]) throw new Error(`party '${id}' already exists`);
  state.parties[id] = { id, name, role, balance: Number(balance) };
  return id;
}

export function registerSkill(state, { id, name, creatorId, price, mode = 'marketplace' }) {
  requireParty(state, creatorId);
  id = id || slug(name);
  if (state.skills[id]) throw new Error(`skill '${id}' already exists`);
  state.skills[id] = {
    id, name, creatorId, mode,
    price: Number(price),
    parentIds: [],
    inheritBps: 0,
    royalty: [{ partyId: creatorId, bps: 10000 }], // creator holds 100% of its own claim by default
  };
  return id;
}

export function forkSkill(state, { id, parentId, creatorId, name, price, inheritBps = 3000 }) {
  const parent = requireSkill(state, parentId);
  requireParty(state, creatorId);
  id = id || slug(name);
  if (state.skills[id]) throw new Error(`skill '${id}' already exists`);
  state.skills[id] = {
    id, name, creatorId, mode: parent.mode,
    price: Number(price),
    parentIds: [parentId],
    inheritBps: clampBps(Number(inheritBps)),
    royalty: [{ partyId: creatorId, bps: 10000 }],
  };
  return id;
}

export function setPrice(state, skillId, price) {
  requireSkill(state, skillId).price = Number(price);
}

export function setInherit(state, skillId, bps) {
  requireSkill(state, skillId).inheritBps = clampBps(Number(bps));
}

export function setFee(state, bps) {
  state.feeBps = clampBps(Number(bps));
}

// holders: [{ partyId, bps }] — must sum to 10000. This is how a Royalty claim is co-held.
export function setRoyalty(state, skillId, holders) {
  const skill = requireSkill(state, skillId);
  const total = holders.reduce((a, h) => a + h.bps, 0);
  if (total !== 10000) throw new Error(`royalty must sum to 10000 bps (got ${total})`);
  for (const h of holders) requireParty(state, h.partyId);
  skill.royalty = holders.map((h) => ({ partyId: h.partyId, bps: clampBps(h.bps) }));
}

// The core economic event. Payment-gated (ADR 0003): pay -> mint credential ->
// consume credential -> execute -> settle.
export function invoke(state, skillId, wielderId) {
  const skill = requireSkill(state, skillId);
  const wielder = requireParty(state, wielderId);
  const price = skill.price;
  if (wielder.balance < price)
    throw new Error(`${wielder.name} can't afford ${money(price)} (balance ${money(wielder.balance)})`);

  // 1. pay
  wielder.balance = round(wielder.balance - price);
  // 2. mint single-use Execution credential
  const credId = `cred-${(state.seq += 1)}`;
  const credential = { id: credId, skillId, wielderId, used: false };
  state.credentials.push(credential);
  // 3. runtime verifies + consumes credential ("no credential, no run")
  credential.used = true;
  // 4. settle: protocol fee, then recursive royalty split through the ancestry
  const fee = round((price * state.feeBps) / 10000);
  state.treasury = round(state.treasury + fee);
  const net = round(price - fee);
  const breakdown = [];
  distribute(state, skillId, net, breakdown, 0);

  const result = {
    type: 'invoke', skillId, skillName: skill.name, wielderId,
    wielderName: wielder.name, price, fee, net, credentialId: credId, breakdown,
    output: `«mock output of ${skill.name}»`,
  };
  state.lastResult = result;
  return result;
}

// Demonstrates the gate: there is no legal way to run without paying first.
export function attemptBypass(state, skillId, wielderId) {
  requireSkill(state, skillId);
  requireParty(state, wielderId);
  throw new Error(
    `NO CREDENTIAL, NO RUN — payment is the meter (ADR 0003). Run \`invoke ${skillId} ${wielderId}\` to pay first.`,
  );
}

// Recursive composable royalty flow-through (ADR 0002). `amount` arrives at a Skill;
// it passes `inheritBps` up to its parent(s) (who recurse), and pays the remainder to
// its own royalty holders.
function distribute(state, skillId, amount, breakdown, depth) {
  const skill = state.skills[skillId];
  let own = amount;
  if (skill.parentIds.length && skill.inheritBps > 0) {
    const up = round((amount * skill.inheritBps) / 10000);
    own = round(amount - up);
    const perParent = round(up / skill.parentIds.length);
    for (const pid of skill.parentIds) distribute(state, pid, perParent, breakdown, depth + 1);
  }
  for (const h of skill.royalty) {
    const amt = round((own * h.bps) / 10000);
    state.parties[h.partyId].balance = round(state.parties[h.partyId].balance + amt);
    breakdown.push({
      partyId: h.partyId,
      partyName: state.parties[h.partyId].name,
      viaSkillId: skillId,
      viaSkillName: skill.name,
      bps: h.bps,
      amount: amt,
      kind: depth === 0 ? 'creator' : 'ancestor',
      depth,
    });
  }
}

// Seed all three modes so there's something to play with immediately.
export function seedDemo(state) {
  Object.assign(state, createState());

  // --- Marketplace: independent creator, Wielder == Beneficiary ---
  addParty(state, { id: 'dana', name: 'Dana (indie creator)', role: 'Creator', balance: 0 });
  addParty(state, { id: 'acme', name: 'Acme Corp', role: 'Wielder/Beneficiary', balance: 1000 });
  registerSkill(state, { id: 'pdfx', name: 'pdf-extract', creatorId: 'dana', price: 10, mode: 'marketplace' });

  // --- Intra-org: employee + employer CO-HOLD the royalty claim (50/50) ---
  addParty(state, { id: 'sam', name: 'Sam (employee)', role: 'Creator', balance: 0 });
  addParty(state, { id: 'megacorp', name: 'MegaCorp (employer)', role: 'Co-owner', balance: 0 });
  addParty(state, { id: 'otherco', name: 'OtherCo (external)', role: 'Wielder/Beneficiary', balance: 1000 });
  registerSkill(state, { id: 'recon', name: 'ledger-recon', creatorId: 'sam', price: 20, mode: 'intra-org' });
  setRoyalty(state, 'recon', [{ partyId: 'sam', bps: 5000 }, { partyId: 'megacorp', bps: 5000 }]);

  // --- Education: school base Skill -> student Derivative -> employer pays ---
  addParty(state, { id: 'stateu', name: 'State U (school)', role: 'Creator', balance: 0 });
  addParty(state, { id: 'mia', name: 'Mia (student->grad)', role: 'Creator', balance: 0 });
  addParty(state, { id: 'biocorp', name: 'BioCorp (employer)', role: 'Wielder/Beneficiary', balance: 1000 });
  registerSkill(state, { id: 'finmod', name: 'fin-modeling (base)', creatorId: 'stateu', price: 5, mode: 'education' });
  forkSkill(state, { id: 'biofin', parentId: 'finmod', creatorId: 'mia', name: 'biotech-fin-modeling', price: 25, inheritBps: 3000 });

  state.lastResult = {
    type: 'note',
    note: 'Seeded 3 modes: marketplace (pdfx), intra-org co-held 50/50 (recon), education chain finmod->biofin (30% flow-through). Try: invoke biofin biocorp',
  };
}

// helper to walk a Skill's ancestry, for display
export function ancestry(state, skillId) {
  const chain = [];
  let cur = state.skills[skillId];
  while (cur && cur.parentIds.length) {
    chain.push(cur.parentIds[0]);
    cur = state.skills[cur.parentIds[0]];
  }
  return chain;
}

// ---- internals ----
function requireParty(state, id) { const p = state.parties[id]; if (!p) throw new Error(`no party '${id}'`); return p; }
function requireSkill(state, id) { const s = state.skills[id]; if (!s) throw new Error(`no skill '${id}'`); return s; }
function clampBps(n) { if (Number.isNaN(n)) throw new Error('bps must be a number'); return Math.max(0, Math.min(10000, Math.round(n))); }
function round(n) { return Math.round(n * 100) / 100; }
function slug(s) { return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 12); }
export function money(n) { return '$' + Number(n).toFixed(2); }

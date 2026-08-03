export const manifesto = {
  title: '“THE PROOF — ARCHIVE”',
  subtitle: 'AN ARCHIVED MANIFESTO FOR THE SOVEREIGNTY OF AUTHORED WORK',
  project: 'SKILL ASSET PROTOCOL',
  preamble: 'This archived manifesto records the project’s earlier authored-work thesis. It is preserved as design history—not as current product doctrine, a legal conclusion, or evidence that the broader compensation model has been validated.',
  principles: [
    { n: '01', head: '“EXPERTISE CAN BECOME AN ASSET.”', body: 'An authored Skill can be governed as a durable work artifact. Legal and economic rights still depend on the governing agreement.' },
    { n: '02', head: '“THE INTERFACE NEED NOT RETURN THE ARTIFACT.”', body: 'The historical seller omitted the Skill file from its response. Model output can still leak or enable reconstruction; extraction resistance is not guaranteed.' },
    { n: '03', head: '“AUTHORIZED PAYMENT BEFORE A PAID RUN.”', body: 'The historical test exercised a payment-gated path once. The website no longer operates that paid endpoint.' },
    { n: '04', head: '“THE WIELDER HAS A WALLET BOUNDARY.”', body: 'The current Wallet Kernel adds customer policy, exact authority, and operator control between an Agent request and any signature.' },
    { n: '05', head: '“PROVENANCE IS DECLARED MEMORY.”', body: 'A ledger can preserve a declaration and its history. It does not prove originality, authorship, safety, or legal ownership.' },
    { n: '06', head: '“COMPENSATION IS A DESIGN CHOICE.”', body: 'Creator compensation remains deferred research. No split or Royalty claim is part of the current v1 offer.' },
    { n: '07', head: '“SECRECY ALONE IS NOT THE MOAT.”', body: 'Evolution may matter, but the retained evidence does not establish durable extraction resistance or clone economics at scale.' },
    { n: '08', head: '“SAY THE QUIET PART ON-CHAIN.”', body: 'Eventually consistent. Unvalidated. Unmeasured. Honesty is a feature, printed on the receipt.' },
    { n: '09', head: '“THE CHAIN IS PLUMBING.”', body: 'Nobody should type a token ticker to get paid for their work.' },
    { n: '10', head: '“PROOF OVER PROMISE.”', body: 'One retained transaction receipt supports one narrow historical claim. Everything else remains bounded or unvalidated.' },
  ],
  proof: {
    heading: '“PROOF”',
    intro: 'Historical evidence, verified 2026-07-17: one successful Base Sepolia test-USDC transfer exists, and the 2026-07-12 run log labels it as the Skill-leg settlement.',
    ledger: '0.25 test USDC · 0xdddf…053f → 0x2500…f189 · block 44053992',
    receipts: [
      { label: 'historical Skill-leg transfer — 0.25 test USDC', tx: '0xaf1ba2fe508ee9d6bfe0823e25a05fc8b05c8dbac007b40b7d36dbbe447af522' },
    ],
    basescan: 'https://sepolia.basescan.org/tx/',
    overhead: 'This receipt does not prove current endpoint behavior, latency, royalty-split correctness, Skill output, demand, or production readiness.',
  },
  doIt: {
    heading: '“ENDPOINT RETIRED”',
    intro: 'The browser-wallet invocation experiment is no longer served by this website. The retained transaction link below is historical evidence, not an invitation to connect a wallet or pay.',
    monopoly: '“STATIC ARCHIVE” — no wallet connection, payment signature, transaction broadcast, or model call is available on this page.',
    steps: ['NO WALLET CONNECTION', 'NO PAYMENT SIGNATURE', 'NO MODEL CALL', 'HISTORICAL RECEIPT ONLY'],
  },
  footer: {
    code: 'https://github.com/Aznatkoiny/skill-asset-protocol',
    license: 'APACHE-2.0',
    credit: 'c/o ANTONY ZAKI — 2026',
    disclaimer: '“RESEARCH” — historical testnet evidence only. No mainnet. Not production-ready.',
  },
};
export type Manifesto = typeof manifesto;

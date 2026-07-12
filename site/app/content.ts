export const manifesto = {
  title: '“THE PROOF”',
  subtitle: 'A MANIFESTO FOR THE SOVEREIGNTY OF AUTHORED WORK',
  project: 'SKILL ASSET PROTOCOL',
  preamble: 'You encoded what you know into an artifact that works without you. Under the old default — “work for hire” — that artifact is confiscated at the moment of its creation. 100 for them. 0 for you. We reject the default.',
  principles: [
    { n: '01', head: '“YOUR EXPERTISE IS AN ASSET.”', body: 'Not a donation. The moment you encode it, it becomes property. Yours.' },
    { n: '02', head: '“THE ARTIFACT IS NEVER HANDED OVER.”', body: 'The world gets the output. The work stays home.' },
    { n: '03', head: '“NO CREDENTIAL, NO RUN.”', body: 'Payment is not a request. It is the key in the ignition.' },
    { n: '04', head: '“THE WIELDER IS A WALLET.”', body: 'Not a platform. Not a harness. Anything that can pay can invoke. No gatekeepers.' },
    { n: '05', head: '“PROVENANCE IS MEMORY.”', body: 'Every fork declares its ancestry, on a ledger no one can edit.' },
    { n: '06', head: '“THE CLAIM IS CO-HELD, NOT SURRENDERED.”', body: '100/0 was a choice, not a law of nature. We choose different splits.' },
    { n: '07', head: '“SECRECY IS NOT THE MOAT.”', body: 'Evolution is. A clone of yesterday’s work competes with what you ship tomorrow.' },
    { n: '08', head: '“SAY THE QUIET PART ON-CHAIN.”', body: 'Eventually consistent. Unvalidated. Unmeasured. Honesty is a feature, printed on the receipt.' },
    { n: '09', head: '“THE CHAIN IS PLUMBING.”', body: 'Nobody should type a token ticker to get paid for their work.' },
    { n: '10', head: '“PROOF OVER PROMISE.”', body: 'A manifesto without receipts is a poster. Scroll down. The receipts are real.' },
  ],
  proof: {
    heading: '“PROOF”',
    intro: 'First real-network run, 2026-07-12. One wallet. Two asset classes. Every cent reconciled on a public chain.',
    ledger: 'claude/plan $0.041 · skill/optimizing-claude-code-prompts $0.25 → creator $0.24375 / treasury $0.00625',
    receipts: [
      { label: 'model invocation — $0.041 settled', tx: '0x01daa723f23a6e2bbfb67b5077a25b37e6b97827b82013152c96da9d0638ff49' },
      { label: 'skill invocation — $0.25 → split', tx: '0xaf1ba2fe508ee9d6bfe0823e25a05fc8b05c8dbac007b40b7d36dbbe447af522' },
    ],
    basescan: 'https://sepolia.basescan.org/tx/',
    overhead: 'payment overhead ≈ 781ms per call. 402 → sign → settle.',
  },
  doIt: {
    heading: '“DO IT YOURSELF”',
    intro: 'This page is not a brochure. It is a metered endpoint. Pay $0.25 in testnet USDC and the hosted skill runs for you — you get the output, never the skill.',
    monopoly: '“MONOPOLY MONEY” — this runs on Base Sepolia, a practice network. The USDC is free from the faucet. Nothing real is at risk.',
    faucet: 'https://faucet.circle.com',
    steps: ['CONNECT A WALLET', 'GET FREE TESTNET USDC', 'PAY $0.25 — SIGN, DON’T SEND', 'RECEIVE OUTPUT. NEVER THE SKILL.'],
  },
  footer: {
    code: 'https://github.com/Aznatkoiny/skill-asset-protocol',
    license: 'APACHE-2.0',
    credit: 'c/o ANTONY ZAKI — 2026',
    disclaimer: '“RESEARCH” — testnet only. Not an offer of securities. The claim is the receipt.',
  },
};
export type Manifesto = typeof manifesto;

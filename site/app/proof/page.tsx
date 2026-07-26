import type { Metadata } from 'next';

import { manifesto } from '../content';
import Manifesto from '../manifesto';

export const metadata: Metadata = {
  title: 'The proof',
  description:
    'Ten principles, real testnet receipts, and the original x402 Skill invocation proof.',
  alternates: { canonical: '/proof' },
  openGraph: {
    title: '“THE PROOF” — a manifesto for the sovereignty of authored work',
    description:
      'Ten principles. Real on-chain receipts. A live x402 endpoint.',
    url: '/proof',
  },
};

export default function ProofPage() {
  return <Manifesto manifesto={manifesto} />;
}

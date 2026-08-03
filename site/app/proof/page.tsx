import type { Metadata } from 'next';

import { manifesto } from '../content';
import Manifesto from '../manifesto';

export const metadata: Metadata = {
  title: 'Archived protocol proof',
  description:
    'An archived manifesto and one bounded historical Base Sepolia test-USDC receipt. No live payment endpoint.',
  alternates: { canonical: '/proof' },
  openGraph: {
    title: '“THE PROOF” — a manifesto for the sovereignty of authored work',
    description:
      'Ten historical principles and one bounded Base Sepolia test-USDC receipt in a static archive.',
    url: '/proof',
  },
};

export default function ProofPage() {
  return <Manifesto manifesto={manifesto} />;
}

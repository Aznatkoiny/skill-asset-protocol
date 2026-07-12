// PROTOTYPE — three variants of the manifesto page, switchable via ?variant=,
// floating bar gated on NEXT_PUBLIC_PROTOTYPE=1.

import { Suspense } from 'react';
import { manifesto } from './content';
import Switcher from './components/Switcher';
import VariantA from './variants/VariantA';
import VariantB from './variants/VariantB';
import VariantC from './variants/VariantC';

export default async function Page({
  searchParams,
}: {
  searchParams: Promise<{ variant?: string }>;
}) {
  const { variant } = await searchParams;
  const v: 'a' | 'b' | 'c' = variant === 'b' ? 'b' : variant === 'c' ? 'c' : 'a';

  return (
    <>
      {v === 'a' && <VariantA manifesto={manifesto} />}
      {v === 'b' && <VariantB manifesto={manifesto} />}
      {v === 'c' && <VariantC manifesto={manifesto} />}
      <Suspense fallback={null}>
        <Switcher />
      </Suspense>
    </>
  );
}

'use client';

// Switcher — floating prototype bar. Fixed bottom-center pill: ← key · name →.
// Wraps a→b→c→a, supports arrow keys (unless typing in an input), and updates
// ?variant= via router.replace. Rendered ONLY when NEXT_PUBLIC_PROTOTYPE === '1'.

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect } from 'react';

const VARIANTS = [
  { key: 'a', name: 'Variant A' },
  { key: 'b', name: 'Variant B' },
  { key: 'c', name: 'Variant C' },
] as const;

export default function Switcher() {
  // Statically inlined at build time — the bar (and its hooks) only exist in
  // prototype builds.
  if (process.env.NEXT_PUBLIC_PROTOTYPE !== '1') return null;
  return <SwitcherBar />;
}

function SwitcherBar() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const raw = searchParams.get('variant');
  const index = Math.max(0, VARIANTS.findIndex((v) => v.key === raw));
  const current = VARIANTS[index];

  const step = useCallback(
    (delta: number) => {
      const next = VARIANTS[(index + delta + VARIANTS.length) % VARIANTS.length];
      const params = new URLSearchParams(searchParams.toString());
      params.set('variant', next.key);
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [index, pathname, router, searchParams],
  );

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      const target = e.target as HTMLElement | null;
      // Don't hijack arrow keys while the user is typing.
      if (
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT' ||
          target.isContentEditable)
      ) {
        return;
      }
      step(e.key === 'ArrowLeft' ? -1 : 1);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [step]);

  return (
    <div className="fixed bottom-4 left-1/2 z-50 flex -translate-x-1/2 items-center gap-3 rounded-full border border-white/20 bg-black/80 px-4 py-2 font-mono text-xs text-white shadow-lg backdrop-blur">
      <button
        type="button"
        aria-label="Previous variant"
        onClick={() => step(-1)}
        className="cursor-pointer rounded-full px-2 py-0.5 hover:bg-white/10"
      >
        ←
      </button>
      <span className="select-none tracking-widest uppercase">
        {current.key.toUpperCase()} · {current.name}
      </span>
      <button
        type="button"
        aria-label="Next variant"
        onClick={() => step(1)}
        className="cursor-pointer rounded-full px-2 py-0.5 hover:bg-white/10"
      >
        →
      </button>
    </div>
  );
}

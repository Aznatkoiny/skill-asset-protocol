'use client';

// VARIANT C — “GALLERY PLACARD” (museum retrospective).
//
// Off-white walls, editorial asymmetric 12-col grid. PROOF hangs FIRST —
// receipts as framed exhibits before a single claim is made. Principles are
// scattered exhibition placards with tombstone captions. One old-style serif
// (EB Garamond) for heads, tiny grotesk for captions. Red (#D32F2F)
// hand-drawn annotation marks. The invoke panel is a participatory exhibit
// with a red DO IT stamp.

import { useState } from 'react';
import { EB_Garamond } from 'next/font/google';
import type { Manifesto } from '../content';
import { useInvoke, type InvokeState } from '../components/useInvoke';

const garamond = EB_Garamond({
  subsets: ['latin'],
  weight: ['400', '500'],
  style: ['normal', 'italic'],
  display: 'swap',
});

const RED = '#D32F2F';
const INK = '#141414';
const WALL = '#F4F1EC';
const CARD = '#FBFAF7';

const TOMBSTONE = 'c/o SKILL ASSET PROTOCOL, 2026 — testnet USDC on chain 84532';

// ---------------------------------------------------------------------------
// Hand-drawn red marks (pure SVG, no images)
// ---------------------------------------------------------------------------

function RoughUnderline({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 300 14"
      preserveAspectRatio="none"
      aria-hidden="true"
      className={className}
    >
      <path
        d="M3 9 C 48 3, 92 12, 148 7 S 246 3, 297 8"
        fill="none"
        stroke={RED}
        strokeWidth="3"
        strokeLinecap="round"
      />
      <path
        d="M14 12 C 70 8, 150 13, 232 9"
        fill="none"
        stroke={RED}
        strokeWidth="1.6"
        strokeLinecap="round"
        opacity="0.8"
      />
    </svg>
  );
}

function RoughArrowUp({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 40 64" aria-hidden="true" className={className}>
      <path
        d="M22 60 C 16 44, 15 28, 19 8"
        fill="none"
        stroke={RED}
        strokeWidth="2.4"
        strokeLinecap="round"
      />
      <path
        d="M10 20 C 13 14, 16 10, 19 6 C 23 10, 27 13, 31 15"
        fill="none"
        stroke={RED}
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function RoughCircleNote({ children }: { children: React.ReactNode }) {
  return (
    <span className="relative inline-block px-3 py-1">
      <svg
        viewBox="0 0 200 60"
        preserveAspectRatio="none"
        aria-hidden="true"
        className="absolute inset-0 h-full w-full"
      >
        <path
          d="M18 30 C 14 10, 70 4, 108 6 C 158 8, 192 14, 190 30 C 188 48, 140 56, 92 55 C 48 54, 20 48, 18 34"
          fill="none"
          stroke={RED}
          strokeWidth="2.2"
          strokeLinecap="round"
        />
      </svg>
      {children}
    </span>
  );
}

function RedAsterisk({ id }: { id?: string }) {
  return (
    <sup id={id} className="ml-0.5 text-[0.75em] font-bold" style={{ color: RED }}>
      *
    </sup>
  );
}

// Tiny red curator’s note — Garamond italic stands in for the hand.
function CuratorNote({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <p
      className={`${garamond.className} italic text-[15px] leading-snug ${className}`}
      style={{ color: RED }}
    >
      {children}
    </p>
  );
}

// Tombstone caption under every placard.
function Tombstone({ line }: { line: string }) {
  return (
    <p className="mt-5 border-t border-[#141414]/25 pt-2.5 text-[9px] uppercase leading-relaxed tracking-[0.18em] text-[#141414]/55">
      {line}
    </p>
  );
}

const shortHash = (tx: string) => `${tx.slice(0, 10)}…${tx.slice(-8)}`;

// ---------------------------------------------------------------------------
// Scatter map — pairs share a wall row on md+, offsets stagger the hang.
// ---------------------------------------------------------------------------
const HANG: string[] = [
  'md:col-start-1 md:col-span-5',
  'md:col-start-7 md:col-span-5 md:mt-24',
  'md:col-start-2 md:col-span-4 md:mt-4',
  'md:col-start-8 md:col-span-5 md:mt-20',
  'md:col-start-1 md:col-span-6 md:mt-6',
  'md:col-start-9 md:col-span-4 md:mt-28',
  'md:col-start-3 md:col-span-4 md:mt-2',
  'md:col-start-8 md:col-span-5 md:mt-16',
  'md:col-start-1 md:col-span-4 md:mt-10',
  'md:col-start-6 md:col-span-7 md:mt-24',
];

const STATE_ORDER: InvokeState[] = ['idle', 'connecting', 'paying', 'running', 'done', 'error'];

const STATE_CAPTION: Record<InvokeState, string> = {
  idle: '“NOT YET PERFORMED” — the exhibit waits for a visitor.',
  connecting: 'wallet requested — switching to chain 84532.',
  paying: '402 received — signing the authorization. no gas, no send.',
  running: 'payment settled — the skill is executing, output streaming home.',
  done: 'performed. output delivered. the artifact never left the building.',
  error: 'condition: interrupted. see the report below.',
};

// Which of the four wall steps a hook state lights up.
const STEP_BY_STATE: Partial<Record<InvokeState, number>> = {
  connecting: 0,
  paying: 2,
  running: 3,
  done: 3,
};

// ---------------------------------------------------------------------------

export default function VariantC({ manifesto }: { manifesto: Manifesto }) {
  const { state, output, paid, error, invoke, needsWallet } = useInvoke();
  const [input, setInput] = useState('');

  const busy = state === 'connecting' || state === 'paying' || state === 'running';
  const activeStep = STEP_BY_STATE[state];

  return (
    <main
      className="min-h-screen text-[#141414] antialiased"
      style={{ backgroundColor: WALL }}
    >
      <div className="mx-auto max-w-[92rem] px-5 pb-24 pt-6 sm:px-8 md:px-14 lg:px-20">
        {/* ================= WALL HEADER ================= */}
        <header>
          <div className="flex items-baseline justify-between gap-4 border-b-2 border-[#141414] pb-3 text-[9px] uppercase tracking-[0.32em] sm:text-[10px]">
            <span className="font-semibold">{manifesto.project}</span>
            <span className="hidden sm:inline text-[#141414]/60">
              A RETROSPECTIVE — HALL 402
            </span>
            <span className="text-[#141414]/60">EST. 2026</span>
          </div>

          <div className="md:grid md:grid-cols-12 md:gap-x-8">
            <div className="pt-10 md:col-span-9 md:pt-16">
              <h1
                className={`${garamond.className} text-[17vw] leading-[0.95] tracking-[-0.01em] sm:text-7xl md:text-8xl lg:text-[9.5rem]`}
              >
                {manifesto.title}
              </h1>
              <RoughUnderline className="mt-2 h-3 w-[62%] max-w-md md:h-4" />
              <p className="mt-6 text-[10px] uppercase tracking-[0.3em] text-[#141414]/75 sm:text-[11px] md:mt-8">
                {manifesto.subtitle}
              </p>
            </div>
            <aside className="mt-8 md:col-span-3 md:mt-auto md:pb-2">
              <p className="text-[9px] uppercase leading-relaxed tracking-[0.18em] text-[#141414]/55">
                EXHIBITION — {TOMBSTONE}. FIRST HUNG 2026-07-12.
              </p>
            </aside>
          </div>

          {/* Wall text (preamble) */}
          <div className="mt-14 md:mt-20 md:grid md:grid-cols-12 md:gap-x-8">
            <p
              className={`${garamond.className} text-2xl leading-[1.35] sm:text-3xl md:col-span-7 md:col-start-1 md:text-[2.1rem]`}
            >
              {manifesto.preamble}
            </p>
            <div className="mt-6 md:col-span-3 md:col-start-10 md:mt-2">
              <CuratorNote>
                the ratio, annotated: 100 / 0 — struck through by the artist. every claim
                in this hall is backed by a receipt, hung first.
              </CuratorNote>
              <RoughArrowUp className="mt-3 hidden h-14 w-9 md:block" />
            </div>
          </div>
        </header>

        {/* ================= PROOF — LEADS THE PAGE ================= */}
        <section aria-label="Proof" className="mt-20 md:mt-32">
          <div className="flex flex-wrap items-end justify-between gap-4 border-b border-[#141414]/40 pb-3">
            <h2 className={`${garamond.className} text-5xl leading-none sm:text-6xl md:text-7xl`}>
              {manifesto.proof.heading}
            </h2>
            <p className="text-[9px] uppercase tracking-[0.28em] text-[#141414]/60">
              GALLERY ONE —{' '}
              <RoughCircleNote>
                <span className="relative font-semibold" style={{ color: RED }}>
                  HUNG BEFORE THE CLAIMS
                </span>
              </RoughCircleNote>
            </p>
          </div>

          <div className="mt-8 md:grid md:grid-cols-12 md:gap-x-8">
            <p className="text-[13px] leading-relaxed text-[#141414]/85 md:col-span-5 md:col-start-1">
              {manifesto.proof.intro}
            </p>
            <div className="mt-4 md:col-span-5 md:col-start-8 md:mt-0">
              <p className="font-mono text-[10px] uppercase leading-relaxed tracking-[0.08em] text-[#141414]/70">
                PROVENANCE LEDGER — {manifesto.proof.ledger}
              </p>
            </div>
          </div>

          {/* Framed exhibits */}
          <div className="mt-12 flex flex-col gap-12 md:grid md:grid-cols-12 md:items-start md:gap-x-8">
            {manifesto.proof.receipts.map((r, i) => (
              <div
                key={r.tx}
                className={
                  i === 0
                    ? 'md:col-start-1 md:col-span-5'
                    : 'md:col-start-7 md:col-span-5 md:mt-20'
                }
              >
                <figure className="border-[3px] border-[#141414] bg-white p-2 shadow-[6px_8px_0_rgba(20,20,20,0.08)]">
                  <div
                    className="border border-[#141414]/50 px-5 py-10 md:px-7 md:py-14"
                    style={{ backgroundColor: CARD }}
                  >
                    <p className="text-[9px] uppercase tracking-[0.3em]" style={{ color: RED }}>
                      EXHIBIT {String(i + 1).padStart(2, '0')} — SETTLED
                    </p>
                    <p className="mt-4 break-all font-mono text-[10px] leading-loose text-[#141414]/80 md:text-[11px]">
                      {r.tx}
                    </p>
                  </div>
                </figure>
                {/* wall plate */}
                <div className="mt-3 border border-[#141414]/35 bg-white px-4 py-3">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.14em]">
                    {r.label}
                  </p>
                  <a
                    href={`${manifesto.proof.basescan}${r.tx}`}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-1.5 inline-block text-[10px] uppercase tracking-[0.14em] underline decoration-2 underline-offset-4 hover:opacity-70"
                    style={{ textDecorationColor: RED }}
                  >
                    {shortHash(r.tx)} — VIEW ON BASESCAN ↗
                  </a>
                  <Tombstone line={`EXHIBIT ${String(i + 1).padStart(2, '0')} — ${TOMBSTONE}`} />
                </div>
              </div>
            ))}
          </div>

          {/* curator's vitrine — the overhead figure */}
          <div className="mt-14 md:grid md:grid-cols-12 md:gap-x-8">
            <div className="border-l-[3px] py-1 pl-5 md:col-span-5 md:col-start-4" style={{ borderColor: RED }}>
              <p className="font-mono text-[11px] leading-relaxed text-[#141414]/80">
                {manifesto.proof.overhead}
                <RedAsterisk />
              </p>
              <CuratorNote className="mt-1.5">* timed, printed, admitted.</CuratorNote>
            </div>
          </div>
        </section>

        {/* ================= PRINCIPLES — SCATTERED PLACARDS ================= */}
        <section aria-label="Principles" className="mt-24 md:mt-36">
          <div className="border-b border-[#141414]/40 pb-3">
            <p className="text-[9px] uppercase tracking-[0.28em] text-[#141414]/60">
              GALLERY TWO — THE PRINCIPLES, CATALOGUED IN ORDER OF CONVICTION
            </p>
          </div>

          <div className="mt-12 flex flex-col gap-10 md:grid md:grid-cols-12 md:items-start md:gap-x-8 md:gap-y-10">
            {manifesto.principles.map((p, i) => {
              const isHonesty = p.n === '08';
              const isProofOverPromise = p.n === '10';
              return (
                <article
                  key={p.n}
                  className={`relative border border-[#141414]/70 px-6 py-7 md:px-8 md:py-9 ${HANG[i]}`}
                  style={{ backgroundColor: CARD }}
                >
                  <p className="flex items-baseline justify-between font-mono text-[9px] uppercase tracking-[0.3em] text-[#141414]/55">
                    <span>CAT. {p.n}</span>
                    <span className="hidden sm:inline">PLACARD</span>
                  </p>
                  <h3
                    className={`${garamond.className} mt-4 text-[1.65rem] leading-[1.08] md:text-[1.9rem] ${
                      isProofOverPromise ? 'md:text-[2.6rem]' : ''
                    }`}
                  >
                    {p.head}
                  </h3>
                  <p className="mt-3.5 text-[11px] leading-relaxed tracking-[0.02em] text-[#141414]/80">
                    {p.body}
                    {isHonesty && <RedAsterisk />}
                    {isProofOverPromise && <RedAsterisk />}
                  </p>

                  {isHonesty && (
                    <CuratorNote className="mt-3">
                      * the caveats are printed on the placard, not buried in the basement.
                    </CuratorNote>
                  )}

                  {isProofOverPromise && (
                    <div className="mt-3 flex items-start gap-2">
                      <RoughArrowUp className="h-12 w-8 shrink-0" />
                      <CuratorNote>
                        * sic — in this hanging the receipts precede the claims. scroll up:
                        gallery one already kept the promise.
                      </CuratorNote>
                    </div>
                  )}

                  <Tombstone line={`“PRINCIPLE ${p.n}” — ${TOMBSTONE}`} />
                </article>
              );
            })}
          </div>
        </section>

        {/* ================= PARTICIPATORY EXHIBIT — DO IT YOURSELF ================= */}
        <section aria-label="Do it yourself" className="mt-24 md:mt-40">
          <div className="md:grid md:grid-cols-12 md:gap-x-8">
            <div className="relative border-[3px] border-[#141414] bg-white p-2 md:col-span-10 md:col-start-2">
              {/* red DO IT stamp */}
              <div
                className="absolute -top-5 right-4 rotate-[-7deg] border-[3px] bg-[#F4F1EC] px-1.5 py-1 md:-top-6 md:right-10"
                style={{ borderColor: RED }}
              >
                <span
                  className="block border px-3 py-1 text-[13px] font-bold uppercase tracking-[0.32em] md:text-base"
                  style={{ borderColor: RED, color: RED }}
                >
                  DO IT
                </span>
              </div>

              <div className="px-5 py-10 sm:px-8 md:px-14 md:py-14" style={{ backgroundColor: CARD }}>
                <p className="text-[9px] uppercase tracking-[0.3em]" style={{ color: RED }}>
                  GALLERY THREE — PARTICIPATORY EXHIBIT. VISITOR OPERATES THE WORK.
                </p>
                <h2 className={`${garamond.className} mt-4 text-5xl leading-none sm:text-6xl md:text-7xl`}>
                  {manifesto.doIt.heading}
                </h2>
                <RoughUnderline className="mt-2 h-3 w-56 md:w-72" />

                <div className="mt-8 md:grid md:grid-cols-10 md:gap-x-10">
                  <p className="text-[13px] leading-relaxed text-[#141414]/85 md:col-span-6">
                    {manifesto.doIt.intro}
                  </p>
                  <div className="mt-5 md:col-span-4 md:mt-0">
                    <p className="text-[11px] leading-relaxed text-[#141414]/80">
                      {manifesto.doIt.monopoly}
                      <RedAsterisk />
                    </p>
                    <CuratorNote className="mt-1.5">* honesty, printed on the wall.</CuratorNote>
                    <a
                      href={manifesto.doIt.faucet}
                      target="_blank"
                      rel="noreferrer"
                      className="mt-4 inline-block border border-[#141414] bg-white px-4 py-2 text-[10px] uppercase tracking-[0.22em] underline decoration-2 underline-offset-4 hover:opacity-70"
                      style={{ textDecorationColor: RED }}
                    >
                      FREE TESTNET USDC — FAUCET.CIRCLE.COM ↗
                    </a>
                  </div>
                </div>

                {/* the four steps — wall instructions */}
                <ol className="mt-10 grid grid-cols-1 border-t border-[#141414]/40 sm:grid-cols-2 lg:grid-cols-4">
                  {manifesto.doIt.steps.map((step, i) => {
                    const lit = activeStep === i;
                    return (
                      <li
                        key={step}
                        className="border-b border-[#141414]/25 py-4 pr-4 lg:border-b-0 lg:border-r lg:last:border-r-0 lg:pl-4 lg:first:pl-0"
                      >
                        <span
                          className={`${garamond.className} block text-3xl leading-none`}
                          style={{ color: lit ? RED : undefined }}
                        >
                          {i + 1}.
                        </span>
                        <span
                          className={`mt-2 block text-[10px] uppercase leading-relaxed tracking-[0.18em] ${
                            lit ? 'font-bold' : 'text-[#141414]/75'
                          }`}
                          style={{ color: lit ? RED : undefined }}
                        >
                          {step}
                          {lit && ' — NOW'}
                        </span>
                      </li>
                    );
                  })}
                </ol>

                {/* condition report — every hook state, surfaced */}
                <div className="mt-10 border border-[#141414]/40 bg-white px-4 py-3">
                  <p className="text-[9px] uppercase tracking-[0.26em] text-[#141414]/55">
                    CONDITION REPORT
                  </p>
                  <p className="mt-2 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] uppercase tracking-[0.12em]">
                    {STATE_ORDER.map((s) => (
                      <span
                        key={s}
                        className={s === state ? 'font-bold' : 'text-[#141414]/35'}
                        style={s === state ? { color: RED } : undefined}
                      >
                        {s === state ? `[${s}]` : s}
                      </span>
                    ))}
                  </p>
                  <p className="mt-2 text-[11px] leading-relaxed text-[#141414]/80">
                    <span
                      className={busy ? 'mr-2 inline-block h-2 w-2 animate-pulse rounded-full align-middle' : 'hidden'}
                      style={{ backgroundColor: RED }}
                    />
                    {STATE_CAPTION[state]}
                  </p>
                </div>

                {/* the instrument */}
                <div className="mt-8">
                  <label
                    htmlFor="variant-c-input"
                    className="block text-[10px] uppercase tracking-[0.22em] text-[#141414]/70"
                  >
                    SUBMIT A PROMPT — THE HOSTED SKILL WILL OPTIMIZE IT
                  </label>
                  <textarea
                    id="variant-c-input"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    disabled={busy}
                    rows={4}
                    placeholder="Paste a rough Claude prompt here. $0.25 buys you the optimized version — never the optimizer."
                    className="mt-3 w-full resize-y border border-[#141414]/70 bg-white p-4 font-mono text-[12px] leading-relaxed placeholder:text-[#141414]/35 focus:outline-none focus:ring-2 focus:ring-[#D32F2F] disabled:opacity-60"
                  />
                  <div className="mt-4 flex flex-wrap items-center gap-4">
                    <button
                      type="button"
                      onClick={() => invoke(input.trim())}
                      disabled={busy || input.trim().length === 0}
                      className="border-[3px] px-8 py-3 text-[12px] font-bold uppercase tracking-[0.28em] transition-opacity hover:opacity-80 disabled:cursor-not-allowed disabled:opacity-40"
                      style={{ borderColor: RED, color: RED, backgroundColor: 'white' }}
                    >
                      {busy ? 'PERFORMING…' : 'INVOKE — $0.25 USDC'}
                    </button>
                    {needsWallet && (
                      <CuratorNote>
                        no wallet detected — install MetaMask (or any injected wallet) to
                        operate this exhibit.
                      </CuratorNote>
                    )}
                  </div>
                </div>

                {/* DONE — the output, framed, with its receipt plate */}
                {state === 'done' && output !== null && (
                  <figure className="mt-10 border-[3px] border-[#141414] bg-white p-2">
                    <div className="border border-[#141414]/50 px-5 py-6 md:px-7" style={{ backgroundColor: WALL }}>
                      <p className="text-[9px] uppercase tracking-[0.3em]" style={{ color: RED }}>
                        OUTPUT — DELIVERED. THE SKILL STAYED HOME.
                      </p>
                      <pre className="mt-4 whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-[#141414]/90">
                        {output}
                      </pre>
                    </div>
                    <figcaption className="px-4 py-3">
                      {paid ? (
                        <a
                          href={`${manifesto.proof.basescan}${paid.txHash}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[10px] font-semibold uppercase tracking-[0.14em] underline decoration-2 underline-offset-4 hover:opacity-70"
                          style={{ textDecorationColor: RED }}
                        >
                          RECEIPT — ${paid.amountUSDC.toFixed(2)} USDC SETTLED — {shortHash(paid.txHash)} — VIEW ON BASESCAN ↗
                        </a>
                      ) : (
                        <p className="text-[10px] uppercase tracking-[0.14em] text-[#141414]/60">
                          RECEIPT — SETTLEMENT HEADER NOT RETURNED. THE OUTPUT ABOVE IS YOURS REGARDLESS.
                        </p>
                      )}
                      <Tombstone line={`YOUR EXHIBIT — ${TOMBSTONE}`} />
                    </figcaption>
                  </figure>
                )}

                {/* ERROR — condition: damaged */}
                {state === 'error' && (
                  <div className="mt-10 border-[3px] px-5 py-5" style={{ borderColor: RED }}>
                    <p className="text-[9px] font-bold uppercase tracking-[0.3em]" style={{ color: RED }}>
                      CONDITION: INTERRUPTED
                    </p>
                    <p className="mt-3 font-mono text-[11px] leading-relaxed text-[#141414]/85">
                      {error ?? 'unknown error'}
                    </p>
                    <CuratorNote className="mt-3">
                      the piece may be re-performed — fix the condition above and invoke again.
                    </CuratorNote>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* ================= COLOPHON ================= */}
        <footer className="mt-24 border-t-2 border-[#141414] pt-6 md:mt-36">
          <div className="flex flex-col gap-6 md:grid md:grid-cols-12 md:gap-x-8">
            <div className="md:col-span-4">
              <a
                href={manifesto.footer.code}
                target="_blank"
                rel="noreferrer"
                className="text-[10px] uppercase tracking-[0.22em] underline decoration-2 underline-offset-4 hover:opacity-70"
                style={{ textDecorationColor: RED }}
              >
                SOURCE — GITHUB ↗
              </a>
              <p className="mt-2 text-[10px] uppercase tracking-[0.22em] text-[#141414]/60">
                LICENSE — {manifesto.footer.license}
              </p>
            </div>
            <div className="md:col-span-4">
              <p className="text-[10px] uppercase tracking-[0.22em] text-[#141414]/60">
                {manifesto.footer.credit}
              </p>
            </div>
            <div className="md:col-span-4">
              <p className="text-[11px] leading-relaxed text-[#141414]/80">
                {manifesto.footer.disclaimer}
                <RedAsterisk />
              </p>
              <CuratorNote className="mt-1.5">* read the placard. then read the chain.</CuratorNote>
            </div>
          </div>
          <p className="mt-10 text-[9px] uppercase tracking-[0.18em] text-[#141414]/40">
            {TOMBSTONE} — END OF EXHIBITION.
          </p>
        </footer>
      </div>
    </main>
  );
}

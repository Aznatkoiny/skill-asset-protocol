// VARIANT A — "THE TEN" (industrial wall text).
//
// A single towering vertical scroll on a white gallery wall: hollow-outlined
// numerals at architectural scale, heads in quotes as display type, bodies
// dense like garment care labels. Diagonal hazard stripes divide the major
// sections. Safety-yellow (#FFD100) appears ONLY on the invoke panel — a
// shipping label / customs form with corner crop marks. The footer is a woven
// garment label.

import Link from 'next/link';

import type { Manifesto } from './content';
import styles from './manifesto.module.css';

const YELLOW = '#FFD100';

const shortTx = (tx: string) => `${tx.slice(0, 10)}…${tx.slice(-8)}`;

/* Hazard-stripe divider between major sections. */
function Hazard() {
  return <div aria-hidden className={styles.hazard} />;
}

/* Registration crop marks at the four corners of the shipping label. */
function CropMarks() {
  return (
    <>
      <span aria-hidden className="absolute -top-3 -left-3 h-6 w-6 border-t-2 border-l-2 border-black" />
      <span aria-hidden className="absolute -top-3 -right-3 h-6 w-6 border-t-2 border-r-2 border-black" />
      <span aria-hidden className="absolute -bottom-3 -left-3 h-6 w-6 border-b-2 border-l-2 border-black" />
      <span aria-hidden className="absolute -right-3 -bottom-3 h-6 w-6 border-r-2 border-b-2 border-black" />
    </>
  );
}

/* Decorative barcode — shipping-label chrome, deterministic widths. */
const BARCODE = [3, 1, 2, 4, 1, 3, 6, 1, 2, 1, 4, 2, 1, 5, 2, 1, 3, 1, 4, 1, 2, 6, 1, 3, 1, 2, 4, 1, 1, 5, 2, 3];
function Barcode() {
  return (
    <div aria-hidden className="flex h-9 items-stretch gap-[2px] md:h-11">
      {BARCODE.map((w, i) => (
        <span key={i} className="bg-black" style={{ width: `${w}px` }} />
      ))}
    </div>
  );
}

export default function VariantA({ manifesto }: { manifesto: Manifesto }) {
  return (
    <main className={`${styles.page} min-h-screen uppercase`}>
      {/* ————— STICKY INDUSTRIAL MASTHEAD STRIP ————— */}
      <header className="sticky top-0 z-40 border-b-2 border-black bg-white">
        <div className="flex items-center justify-between px-4 py-2 text-[10px] font-bold tracking-[0.25em] md:px-8">
          <span>{manifesto.project}</span>
          <span className="hidden sm:inline">ARCHIVED EXPERIMENT</span>
          <span aria-hidden>N&ordm; 402</span>
        </div>
      </header>

      <div className="flex flex-wrap items-center justify-between gap-3 bg-black px-4 py-3 text-[10px] font-bold tracking-[0.16em] text-white md:px-8">
        <p>STATIC HISTORY — NOT THE CURRENT PRODUCT OR A LIVE PAYMENT ENDPOINT</p>
        <Link className="border-b border-white" href="/">
          EXPLORE HUMAN CHOICE &rarr;
        </Link>
      </div>

      {/* ————— MASTHEAD: TITLE / SUBTITLE / PREAMBLE ————— */}
      <section className="px-4 pt-16 pb-20 md:px-8 md:pt-28 md:pb-36">
        <p className="text-[10px] font-bold tracking-[0.3em] md:text-[11px]">{manifesto.subtitle}</p>
        <h1 className="mt-6 text-[clamp(3.2rem,15vw,12rem)] leading-[0.9] font-bold tracking-[-0.03em]">
          {manifesto.title}
        </h1>
        <p className="mt-12 max-w-xl border-t-2 border-black pt-4 text-[12px] leading-[1.9] font-bold tracking-[0.08em] md:text-[13px]">
          {manifesto.preamble}
        </p>
        <p aria-hidden className="mt-14 text-[9px] font-bold tracking-[0.3em] opacity-60">
          SCROLL &darr; — 10 HISTORICAL PRINCIPLES · 1 VERIFIED RECEIPT · NO LIVE ENDPOINT
        </p>
      </section>

      <Hazard />

      {/* ————— THE TEN — WALL TEXT ————— */}
      <section aria-label="The ten principles">
        <div className="px-4 pt-16 pb-6 md:px-8 md:pt-24 md:pb-10">
          <p className="text-[10px] font-bold tracking-[0.3em]">INDEX — TEN PRINCIPLES</p>
          <h2 className="mt-3 text-[clamp(2.4rem,9vw,7rem)] leading-none font-bold tracking-[-0.02em]">
            &ldquo;THE TEN&rdquo;
          </h2>
        </div>

        {manifesto.principles.map((p) => (
          <article key={p.n} className="border-t border-black px-4 py-20 md:px-8 md:py-36">
            <div className="flex items-baseline justify-between text-[10px] font-bold tracking-[0.25em]">
              <span>PRINCIPLE {p.n}/10</span>
              <span aria-hidden>&ldquo;WALL TEXT&rdquo;</span>
            </div>
            <div aria-hidden className={`${styles.hollow} mt-4 text-[clamp(6rem,30vw,22rem)] leading-[0.8] font-bold`}>
              {p.n}
            </div>
            <h3 className="mt-6 max-w-4xl text-[clamp(1.5rem,5.5vw,4rem)] leading-[1.02] font-bold tracking-[-0.01em]">
              {p.head}
            </h3>
            <p className="mt-8 max-w-md border-t-2 border-black pt-3 text-[11px] leading-[1.8] font-bold tracking-[0.12em]">
              {p.body}
            </p>
          </article>
        ))}
      </section>

      <Hazard />

      {/* ————— PROOF — THE RECEIPTS ————— */}
      <section id="proof" aria-label="Proof" className="px-4 py-20 md:px-8 md:py-32">
        <div className="flex items-baseline justify-between text-[10px] font-bold tracking-[0.25em]">
          <span>SECTION — EVIDENCE</span>
          <span aria-hidden>&ldquo;ONE RECEIPT&rdquo;</span>
        </div>
        <h2 className="mt-4 text-[clamp(2.4rem,10vw,7rem)] leading-none font-bold tracking-[-0.02em]">
          {manifesto.proof.heading}
        </h2>
        <p className="mt-8 max-w-xl text-[12px] leading-[1.9] font-bold tracking-[0.08em] md:text-[13px]">
          {manifesto.proof.intro}
        </p>

        <div className="mt-10 max-w-2xl border-2 border-black">
          <p className="border-b-2 border-black px-3 py-2 text-[9px] font-bold tracking-[0.25em]">
            HISTORICAL TRANSFER — ONE RECEIPT VERIFIED
          </p>
          <p className="px-3 py-4 font-mono text-[11px] leading-[1.9] normal-case md:text-[12px]">
            {manifesto.proof.ledger}
          </p>
        </div>

        <ul className="mt-6 max-w-2xl">
          {manifesto.proof.receipts.map((r) => (
            <li key={r.tx} className="mt-3 first:mt-0">
              <a
                href={`${manifesto.proof.basescan}${r.tx}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 border-2 border-black px-3 py-3 text-[10px] font-bold tracking-[0.12em] transition-colors hover:bg-black hover:text-white"
              >
                <span>{r.label}</span>
                <span className="font-mono normal-case">
                  {shortTx(r.tx)} &nearr; SEPOLIA.BASESCAN.ORG
                </span>
              </a>
            </li>
          ))}
        </ul>

        <p className="mt-8 max-w-xl text-[10px] leading-[1.8] font-bold tracking-[0.15em] opacity-70">
          {manifesto.proof.overhead}
        </p>
      </section>

      <Hazard />

      {/* ————— DO IT YOURSELF — SHIPPING LABEL / CUSTOMS FORM ————— */}
      <section id="invoke" aria-label="Retired endpoint archive" className="px-6 py-20 md:px-8 md:py-32">
        <div
          className="relative mx-auto max-w-3xl border-2 border-black p-5 md:p-10"
          style={{ background: YELLOW }}
        >
          <CropMarks />

          {/* Label header */}
          <div className="flex flex-wrap items-start justify-between gap-4 border-b-2 border-black pb-5">
            <div>
              <p className="text-[9px] font-bold tracking-[0.3em]">
                SHIPPING LABEL / CUSTOMS FORM — N&ordm; 402
              </p>
              <h2 className="mt-2 text-[clamp(1.9rem,7vw,4rem)] leading-[0.95] font-bold tracking-[-0.02em]">
                {manifesto.doIt.heading}
              </h2>
            </div>
            <Barcode />
          </div>

          <p className="mt-6 max-w-xl text-[11px] leading-[1.9] font-bold tracking-[0.08em] md:text-[12px]">
            {manifesto.doIt.intro}
          </p>

          {/* Static archive notice */}
          <div className="mt-6 border-2 border-dashed border-black p-4">
            <p className="text-[10px] leading-[1.8] font-bold tracking-[0.12em]">
              {manifesto.doIt.monopoly}
            </p>
          </div>

          {/* The four steps — form fields */}
          <div className="mt-8">
            <p className="text-[9px] font-bold tracking-[0.3em]">HANDLING INSTRUCTIONS — 4 STEPS</p>
            <ol className="mt-3 border-2 border-black">
              {manifesto.doIt.steps.map((s, i) => (
                <li
                  key={s}
                  className="flex items-center gap-4 border-b-2 border-black px-3 py-3 last:border-b-0"
                >
                  <span aria-hidden className={`${styles.hollowSm} w-12 shrink-0 text-3xl leading-none font-bold`}>
                    0{i + 1}
                  </span>
                  <span className="text-[11px] font-bold tracking-[0.15em]">{s}</span>
                </li>
              ))}
            </ol>
          </div>

          <div className="mt-8 border-2 border-black bg-white p-4">
            <p className="text-[10px] leading-[1.8] font-bold tracking-[0.12em]">
              RETIRED — NO WALLET CONNECTION OR PAYMENT IS AVAILABLE ON THIS
              WEBSITE.
            </p>
            <p className="mt-2 font-mono text-[10px] leading-relaxed normal-case">
              Current development belongs in the customer-hosted Wallet Kernel,
              behind explicit policy and release evidence gates.
            </p>
          </div>
        </div>
      </section>

      <Hazard />

      {/* ————— FOOTER — WOVEN GARMENT LABEL ————— */}
      <footer className="px-4 py-20 md:py-32">
        <div className="mx-auto max-w-xs border border-black p-1">
          <div className={`${styles.weave} border border-black px-6 py-8 text-center`}>
            <p className="text-[11px] font-bold tracking-[0.3em]">{manifesto.project}</p>
            <p className="mt-1 text-[9px] font-bold tracking-[0.2em]">{manifesto.footer.license}</p>
            <div aria-hidden className="mx-auto my-5 h-px w-16 bg-black" />
            <p className="text-[9px] font-bold tracking-[0.15em]">{manifesto.footer.credit}</p>
            <p className="mt-4 text-[8px] leading-[1.9] font-bold tracking-[0.12em]">
              {manifesto.footer.disclaimer}
            </p>
            <p className="mt-5">
              <a
                href={manifesto.footer.code}
                target="_blank"
                rel="noopener noreferrer"
                className="border-b border-black text-[9px] font-bold tracking-[0.2em] hover:bg-black hover:text-white"
              >
                &ldquo;SOURCE&rdquo; &rarr; GITHUB &nearr;
              </a>
            </p>
            <p aria-hidden className="mt-6 text-[7px] font-bold tracking-[0.2em] opacity-60">
              ARCHIVED MANIFESTO · STATIC RECEIPT · NO LIVE ENDPOINT
            </p>
          </div>
        </div>
      </footer>
    </main>
  );
}

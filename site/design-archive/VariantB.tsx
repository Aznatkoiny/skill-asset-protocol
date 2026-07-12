'use client';

// VARIANT B — "RECEIPT". The manifesto as a point-of-sale receipt / protocol
// log. Pure black, phosphor-white ui-monospace, one narrow ~46ch thermal-paper
// column. Principles are LINE ITEMS. The proof section is a settlement
// receipt. The invoke panel is a terminal prompt whose states stream as log
// lines. Zero large type. Density maximal.

import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { Manifesto } from '../content';
import { useInvoke, type InvokeState } from '../components/useInvoke';
import styles from './VariantB.module.css';

const DIM = 'text-[#7f997f]';
const RULE = 'border-[#334133]';

const PHASE_LINES: Partial<Record<InvokeState, string>> = {
  connecting: '[connecting] wallet handshake → base-sepolia (84532)',
  paying: '[paying]     HTTP 402 → signing EIP-3009 — sign, don’t send',
  running: '[running]    authorization settled — skill executing',
  done: '[done]       exit 0 — output received. never the skill.',
  error: '[error]      process exited non-zero',
};

const DEFAULT_INPUT = 'Optimize this prompt: “summarize my meeting notes”';

// --- receipt primitives -------------------------------------------------------

function Rule({ dashed = true }: { dashed?: boolean }) {
  return (
    <div
      aria-hidden
      className={`my-3 border-t ${dashed ? 'border-dashed' : ''} ${RULE}`}
    />
  );
}

function Tear() {
  return (
    <div aria-hidden className={`my-5 flex items-center gap-2 ${DIM}`}>
      <span>✂</span>
      <span className={`flex-1 border-t border-dashed ${RULE}`} />
      <span className="tracking-[0.3em]">TEAR HERE</span>
      <span className={`flex-1 border-t border-dashed ${RULE}`} />
    </div>
  );
}

function Row({ l, r }: { l: string; r: string }) {
  return (
    <div className="flex items-baseline">
      <span className="shrink-0">{l}</span>
      <span
        aria-hidden
        className={`mx-2 mb-[3px] min-w-[2ch] flex-1 border-b border-dotted ${RULE}`}
      />
      <span className="shrink-0 text-right">{r}</span>
    </div>
  );
}

function SectionHead({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-center font-bold tracking-[0.25em]">{children}</div>
  );
}

// --- the page -----------------------------------------------------------------

export default function VariantB({ manifesto }: { manifesto: Manifesto }) {
  const { state, output, paid, error, invoke, needsWallet } = useInvoke();
  const [input, setInput] = useState('');
  const [log, setLog] = useState<string[]>([]);
  const prevState = useRef<InvokeState>('idle');

  const busy = state === 'connecting' || state === 'paying' || state === 'running';

  // Stream state transitions as terminal log lines. A new run (idle →
  // connecting) resets the log; each subsequent phase appends one line.
  useEffect(() => {
    if (state === prevState.current) return;
    prevState.current = state;
    const line = PHASE_LINES[state];
    if (!line) return;
    setLog((l) => (state === 'connecting' ? [line] : [...l, line]));
  }, [state]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    void invoke(input.trim() || DEFAULT_INPUT);
  };

  const { proof, doIt, footer } = manifesto;

  return (
    <main className="min-h-screen bg-black py-8 text-[#eaffea]">
      <div
        className={`${styles.paper} mx-auto w-full max-w-[46ch] px-4 text-[11px] leading-[1.65] sm:text-[12px]`}
      >
        {/* ── HEADER ─────────────────────────────────────────────── */}
        <Tear />
        <div className="text-center">
          <div className="font-bold tracking-[0.3em]">{manifesto.project}</div>
          <div aria-hidden className={DIM}>
            * * * * * * * * * * * * * * * *
          </div>
          <div className="mt-2 font-bold tracking-[0.2em]">{manifesto.title}</div>
          <div className={`mt-1 ${DIM}`}>{manifesto.subtitle}</div>
          <div aria-hidden className={`mt-2 ${DIM}`}>
            * * * * * * * * * * * * * * * *
          </div>
        </div>

        <div className="mt-3">
          <Row l="REG" r="402" />
          <Row l="TERMINAL" r="BASE-SEPOLIA / 84532" />
          <Row l="DATE" r="2026-07-12" />
          <Row l="CASHIER" r="x402 FACILITATOR" />
          <Row l="COPY" r="“CUSTOMER”" />
        </div>

        <Rule />

        {/* ── PREAMBLE ───────────────────────────────────────────── */}
        <div className={`text-center tracking-[0.25em] ${DIM}`}>— NOTICE —</div>
        <p className="mt-2">{manifesto.preamble}</p>

        <Rule />

        {/* ── LINE ITEMS ─────────────────────────────────────────── */}
        <div className="flex font-bold">
          <span className="min-w-0 flex-1">ITEM</span>
          <span className="w-[5ch] shrink-0 text-right">QTY</span>
          <span className="w-[11ch] shrink-0 text-right">AMT</span>
        </div>
        <div aria-hidden className={`border-t border-dashed ${RULE}`} />

        <ol className="list-none">
          {manifesto.principles.map((p) => (
            <li key={p.n} className="mt-3">
              <div className="flex gap-[1ch]">
                <span className="w-[2ch] shrink-0">{p.n}</span>
                <span className="min-w-0 flex-1 font-bold">{p.head}</span>
              </div>
              <p className={`pl-[3ch] ${DIM}`}>{p.body}</p>
              <div className="flex pl-[3ch]">
                <span className={`min-w-0 flex-1 ${DIM}`}>SKU SAP-{p.n}</span>
                <span className="w-[5ch] shrink-0 text-right">1</span>
                <span className="w-[11ch] shrink-0 text-right">NO REFUNDS</span>
              </div>
            </li>
          ))}
        </ol>

        <Rule />
        <Row l={`SUBTOTAL (${manifesto.principles.length} ITEMS)`} r="“PRICELESS”" />
        <Row l="TAX — WORK-FOR-HIRE" r="VOID" />
        <Row l="DISCOUNT — 100/0 DEFAULT" r="REJECTED" />

        <Tear />

        {/* ── PROOF — SETTLEMENT RECEIPT ─────────────────────────── */}
        <SectionHead>{proof.heading} — SETTLEMENT</SectionHead>
        <p className={`mt-2 ${DIM}`}>{proof.intro}</p>

        {proof.receipts.map((r) => (
          <div key={r.tx} className="mt-3">
            <div className="font-bold">{r.label}</div>
            <div className="break-all">
              <span className={DIM}>TX </span>
              <a
                href={`${proof.basescan}${r.tx}`}
                target="_blank"
                rel="noreferrer"
                className={`${DIM} underline decoration-dotted underline-offset-2 hover:text-[#eaffea]`}
              >
                {r.tx}
              </a>
            </div>
          </div>
        ))}

        <div className={`mt-3 border-t border-b border-dashed ${RULE} py-2`}>
          <div className="flex justify-between font-bold">
            <span>TOTAL</span>
            <span>“SETTLED”</span>
          </div>
          <div className="mt-1 break-words">{proof.ledger}</div>
        </div>
        <p className={`mt-2 ${DIM}`}>{proof.overhead}</p>

        <Tear />

        {/* ── DO IT YOURSELF — TERMINAL ──────────────────────────── */}
        <SectionHead>{doIt.heading}</SectionHead>
        <p className="mt-2">{doIt.intro}</p>
        <p className={`mt-2 ${DIM}`}>
          {doIt.monopoly}{' '}
          <a
            href={doIt.faucet}
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted underline-offset-2 hover:text-[#eaffea]"
          >
            FAUCET → faucet.circle.com
          </a>
        </p>

        <div className="mt-3">
          {doIt.steps.map((s, i) => (
            <Row
              key={s}
              l={`[${i + 1}] ${s}`}
              r={i === 2 ? '$0.25' : i === 3 ? 'YOURS' : 'FREE'}
            />
          ))}
        </div>

        <Rule />

        {/* terminal prompt */}
        <div className="whitespace-pre-wrap break-words">
          <span className={DIM}>$</span> invoke --pay 0.25 \{'\n'}
          {'    '}optimizing-claude-code-prompts \{'\n'}
          {'    '}--network base-sepolia
        </div>

        <form onSubmit={onSubmit} className="mt-2">
          <label className="flex items-baseline gap-2">
            <span className={`shrink-0 ${DIM}`}>&gt; input:</span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={DEFAULT_INPUT}
              disabled={busy}
              className={`w-full min-w-0 flex-1 border-b border-dotted ${RULE} bg-transparent text-[#eaffea] placeholder-[#516451] outline-none focus:border-[#eaffea] disabled:opacity-40`}
            />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="mt-3 w-full border border-[#eaffea] px-2 py-2 text-center font-bold tracking-[0.25em] transition-colors hover:bg-[#eaffea] hover:text-black disabled:cursor-wait disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-[#eaffea]"
          >
            {busy ? 'PROCESSING…' : '↵ RUN — “$0.25”'}
          </button>
        </form>

        {needsWallet && (
          <div className="mt-3 break-words">
            <span className="bg-[#eaffea] px-1 font-bold text-black">!</span>{' '}
            NO INJECTED WALLET DETECTED — INSTALL METAMASK (OR ANY EIP-1193
            WALLET) TO PAY.
          </div>
        )}

        {/* state log — every hook state surfaces here */}
        <div className={`mt-3 ${DIM}`}>
          {log.map((line, i) => (
            <div key={i} className="whitespace-pre-wrap break-words">
              {line}
            </div>
          ))}
          {state === 'idle' && (
            <div className="whitespace-pre-wrap">
              [idle]       awaiting invocation
              <span className={styles.cursor} aria-hidden />
            </div>
          )}
          {busy && (
            <div className="whitespace-pre-wrap">
              …<span className={styles.cursor} aria-hidden />
            </div>
          )}
        </div>
        <div className="mt-2">
          <Row l="STATE" r={state.toUpperCase()} />
        </div>

        {state === 'error' && error && (
          <div className="mt-3">
            <div className="break-words">
              <span className="bg-[#eaffea] px-1 font-bold text-black">
                VOID
              </span>{' '}
              {error}
            </div>
            <div className={`mt-1 ${DIM}`}>
              “NOTHING WAS CHARGED THAT DID NOT SETTLE.”
            </div>
          </div>
        )}

        {state === 'done' && (
          <div className="mt-3">
            {paid && (
              <div className="break-all">
                <div className="font-bold">
                  PAID ${paid.amountUSDC.toFixed(2)} USDC — SETTLED
                </div>
                <span className={DIM}>TX </span>
                <a
                  href={`https://sepolia.basescan.org/tx/${paid.txHash}`}
                  target="_blank"
                  rel="noreferrer"
                  className={`${DIM} underline decoration-dotted underline-offset-2 hover:text-[#eaffea]`}
                >
                  {paid.txHash}
                </a>
              </div>
            )}
            <div className={`mt-2 border-t border-dashed ${RULE} pt-2`}>
              <div className={`text-center tracking-[0.2em] ${DIM}`}>
                — OUTPUT · “CUSTOMER COPY” —
              </div>
              <pre className="mt-1 whitespace-pre-wrap break-words font-[inherit]">
                {output}
              </pre>
            </div>
          </div>
        )}

        <Tear />

        {/* ── FOOTER ─────────────────────────────────────────────── */}
        <p className={DIM}>{footer.disclaimer}</p>
        <div className="mt-2">
          <Row l="LICENSE" r={footer.license} />
        </div>
        <div className="mt-1 break-all">
          <span>CODE </span>
          <a
            href={footer.code}
            target="_blank"
            rel="noreferrer"
            className={`${DIM} underline decoration-dotted underline-offset-2 hover:text-[#eaffea]`}
          >
            {footer.code.replace('https://', '')}
          </a>
        </div>
        <div className="mt-1">{footer.credit}</div>

        <div className={`${styles.barcode} mt-6`} aria-hidden />
        <div className="mt-1 text-center tracking-[0.4em]">SAP-402-2026</div>
        <div className={`mt-4 text-center ${DIM}`}>
          * THANK YOU FOR YOUR SOVEREIGNTY *
        </div>
        <div className="text-center">
          NO EXCHANGES · NO REFUNDS · NO CUSTODY
          <span className={styles.cursor} aria-hidden />
        </div>
        <div className="h-10" aria-hidden />
      </div>
    </main>
  );
}

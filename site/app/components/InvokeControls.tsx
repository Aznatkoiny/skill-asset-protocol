'use client';

import { useState } from 'react';

import { useInvoke, type InvokeState } from './useInvoke';

const STATES: { key: InvokeState; label: string }[] = [
  { key: 'idle', label: 'IDLE' },
  { key: 'connecting', label: 'CONNECTING' },
  { key: 'paying', label: 'PAYING' },
  { key: 'running', label: 'RUNNING' },
  { key: 'done', label: 'DONE' },
  { key: 'error', label: 'ERROR' },
];

const STATUS_LINE: Record<InvokeState, string> = {
  idle: 'AWAITING INSTRUCTION. NOTHING SIGNED, NOTHING SENT.',
  connecting: 'CONNECTING WALLET — SWITCHING CHAIN TO BASE SEPOLIA.',
  paying: '402 RECEIVED — SIGN, DON’T SEND. THE FACILITATOR SETTLES.',
  running: 'PAYMENT SETTLED — SKILL EXECUTING. OUTPUT INBOUND.',
  done: 'DELIVERED. YOU GOT THE OUTPUT. THE SKILL STAYED HOME.',
  error: 'STOPPED. SEE INCIDENT REPORT BELOW.',
};

const shortTx = (tx: string) => `${tx.slice(0, 10)}…${tx.slice(-8)}`;

export function InvokeControls({ basescan }: { basescan: string }) {
  const { state, output, paid, error, account, connect, invoke, needsWallet } =
    useInvoke();
  const [input, setInput] = useState('');
  const busy =
    state === 'connecting' || state === 'paying' || state === 'running';

  return (
    <>
      <div className="mt-8">
        <p className="text-[9px] font-bold tracking-[0.3em]">
          FIELD 04 — SIGNATORY (STEP 01: CONNECT A WALLET)
        </p>
        {account ? (
          <p className="mt-2 inline-block border-2 border-black bg-white px-3 py-2 font-mono text-[11px] normal-case">
            CONNECTED — {shortTx(account)} · BASE SEPOLIA
          </p>
        ) : (
          <button
            type="button"
            onClick={() => void connect()}
            disabled={busy}
            className="mt-2 cursor-pointer border-2 border-black bg-white px-4 py-3 text-[11px] font-bold tracking-[0.2em] transition-colors hover:bg-black hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            {state === 'connecting' ? 'CONNECTING…' : '“CONNECT A WALLET”'}
          </button>
        )}
      </div>

      <div className="mt-8">
        <label
          htmlFor="variant-a-input"
          className="text-[9px] font-bold tracking-[0.3em]"
        >
          FIELD 05 — DECLARE CONTENTS (A PROMPT TO OPTIMIZE)
        </label>
        <textarea
          id="variant-a-input"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          disabled={busy}
          rows={4}
          placeholder="PASTE A CLAUDE CODE PROMPT HERE. THE HOSTED SKILL OPTIMIZES IT AND SHIPS THE RESULT BACK."
          className="mt-2 w-full resize-y border-2 border-black bg-white p-3 font-mono text-[12px] leading-relaxed normal-case outline-none placeholder:uppercase placeholder:opacity-40 disabled:opacity-60"
        />
        <button
          type="button"
          onClick={() => void invoke(input.trim())}
          disabled={busy || input.trim().length === 0}
          className="mt-3 w-full cursor-pointer border-2 border-black bg-black px-8 py-4 text-[13px] font-bold tracking-[0.3em] text-[#FFD100] transition-colors hover:bg-white hover:text-black disabled:cursor-not-allowed disabled:opacity-40 md:w-auto"
        >
          {busy ? 'IN TRANSIT…' : '“INVOKE” — PAY $0.25'}
        </button>
        {input.trim().length === 0 && !busy && (
          <p className="mt-2 text-[8px] font-bold tracking-[0.25em] opacity-60">
            FIELD 05 REQUIRED — EMPTY PARCELS DO NOT SHIP.
          </p>
        )}
      </div>

      <div className="mt-8 border-t-2 border-black pt-5">
        <p className="text-[9px] font-bold tracking-[0.3em]">
          TRACKING — STATE MACHINE
        </p>
        <ol className="mt-3 flex flex-wrap items-center gap-1">
          {STATES.map((status, index) => (
            <li key={status.key} className="flex items-center gap-1">
              {index > 0 && (
                <span aria-hidden className="text-[9px] font-bold">
                  &rarr;
                </span>
              )}
              <span
                className={`border-2 border-black px-2 py-1 text-[9px] font-bold tracking-[0.15em] ${
                  state === status.key
                    ? `bg-black text-[#FFD100] ${busy ? 'animate-pulse' : ''}`
                    : 'text-black'
                }`}
              >
                {status.label}
              </span>
            </li>
          ))}
        </ol>
        <p
          aria-live="polite"
          className="mt-3 text-[10px] font-bold tracking-[0.15em]"
        >
          STATUS: {STATUS_LINE[state]}
        </p>
      </div>

      {needsWallet && (
        <p className="mt-4 border-2 border-dashed border-black p-3 text-[10px] leading-[1.8] font-bold tracking-[0.12em]">
          NO WALLET DETECTED — INSTALL METAMASK (OR ANY INJECTED WALLET) TO PAY. THE WIELDER IS A WALLET.
        </p>
      )}

      {state === 'error' && error && (
        <div className="mt-4 border-2 border-black bg-white">
          <p className="border-b-2 border-black px-3 py-2 text-[9px] font-bold tracking-[0.25em]">
            &ldquo;INCIDENT REPORT&rdquo;
          </p>
          <p className="p-4 font-mono text-[11px] leading-relaxed break-words normal-case">
            {error}
          </p>
        </div>
      )}

      {state === 'done' && output !== null && (
        <div className="mt-4 border-2 border-black bg-white">
          <p className="border-b-2 border-black px-3 py-2 text-[9px] font-bold tracking-[0.25em]">
            &ldquo;OUTPUT&rdquo; — YOURS. THE SKILL — NOT INCLUDED.
          </p>
          <pre className="max-h-96 overflow-auto p-4 font-mono text-[11px] leading-relaxed whitespace-pre-wrap normal-case">
            {output}
          </pre>
        </div>
      )}

      {paid && (
        <a
          href={`${basescan}${paid.txHash}`}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-4 flex flex-wrap items-center justify-between gap-x-6 gap-y-1 border-2 border-black bg-white px-3 py-3 text-[10px] font-bold tracking-[0.12em] transition-colors hover:bg-black hover:text-white"
        >
          <span>
            &ldquo;RECEIPT&rdquo; — ${paid.amountUSDC.toFixed(2)} USDC SETTLED
          </span>
          <span className="font-mono normal-case">
            {shortTx(paid.txHash)} &nearr; SEPOLIA.BASESCAN.ORG
          </span>
        </a>
      )}
    </>
  );
}

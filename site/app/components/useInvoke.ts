'use client';

// useInvoke — headless hook wrapping the x402 pay-and-invoke flow against
// /api/invoke/optimizing-claude-code-prompts. Variants style it themselves.
//
// State machine:
//   idle → connecting (wallet + chain) → paying (402 → sign → settle)
//        → running (skill executing / response streaming) → done | error
//
// connect() is the standalone STEP 01: wallet connect + chain switch with no
// payment attached. invoke() reuses the session when one exists.

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  connectWallet,
  ensureBaseSepolia,
  hasWallet,
  payAndFetch,
  type PaidReceipt,
  type WalletSession,
} from '../lib/x402-client';

export type InvokeState = 'idle' | 'connecting' | 'paying' | 'running' | 'done' | 'error';

export interface InvokeResult {
  state: InvokeState;
  output: string | null;
  paid: PaidReceipt | null;
  error: string | null;
  account: string | null;
  connect: () => Promise<void>;
  invoke: (input: string) => Promise<void>;
  needsWallet: boolean;
}

const SKILL_ENDPOINT = '/api/invoke/optimizing-claude-code-prompts';

export function useInvoke(): InvokeResult {
  const [state, setState] = useState<InvokeState>('idle');
  const [output, setOutput] = useState<string | null>(null);
  const [paid, setPaid] = useState<PaidReceipt | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [account, setAccount] = useState<string | null>(null);
  const sessionRef = useRef<WalletSession | null>(null);
  // Detected in an effect (not during render) to avoid SSR hydration mismatches.
  const [needsWallet, setNeedsWallet] = useState(false);

  useEffect(() => {
    setNeedsWallet(!hasWallet());
  }, []);

  const openSession = useCallback(async (): Promise<WalletSession> => {
    if (!hasWallet()) {
      setNeedsWallet(true);
      throw new Error('No wallet detected — install MetaMask (or any injected wallet) to pay.');
    }
    const session = await connectWallet();
    sessionRef.current = session;
    setAccount(session.account);
    return session;
  }, []);

  const connect = useCallback(async () => {
    setError(null);
    setState('connecting');
    try {
      await openSession();
      setState('idle');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setState('error');
    }
  }, [openSession]);

  const invoke = useCallback(
    async (input: string) => {
      setError(null);
      setOutput(null);
      setPaid(null);
      setState('connecting');
      try {
        const session = sessionRef.current ?? (await openSession());
        // The user may have moved networks since connecting; no-op when not.
        await ensureBaseSepolia(session.provider);

        setState('paying');
        const { response, paid: receipt } = await payAndFetch(
          SKILL_ENDPOINT,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ input }),
          },
          session,
        );

        setState('running');
        const data = (await response.json().catch(() => null)) as {
          output?: string;
          paid?: PaidReceipt;
          error?: string;
        } | null;

        if (!response.ok) {
          throw new Error(data?.error ?? `invoke failed with status ${response.status}`);
        }

        setOutput(data?.output ?? '');
        setPaid(data?.paid ?? receipt ?? null);
        setState('done');
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setState('error');
      }
    },
    [openSession],
  );

  return { state, output, paid, error, account, connect, invoke, needsWallet };
}

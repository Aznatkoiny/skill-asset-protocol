'use client';

// useInvoke — headless hook wrapping the x402 pay-and-invoke flow against
// /api/invoke/optimizing-claude-code-prompts. Variants style it themselves.
//
// State machine:
//   idle → connecting (wallet + chain) → paying (402 → sign → settle)
//        → running (skill executing / response streaming) → done | error

import { useCallback, useEffect, useState } from 'react';
import { ensureBaseSepolia, payAndFetch, type PaidReceipt } from '../lib/x402-client';

export type InvokeState = 'idle' | 'connecting' | 'paying' | 'running' | 'done' | 'error';

export interface InvokeResult {
  state: InvokeState;
  output: string | null;
  paid: PaidReceipt | null;
  error: string | null;
  invoke: (input: string) => Promise<void>;
  needsWallet: boolean;
}

const SKILL_ENDPOINT = '/api/invoke/optimizing-claude-code-prompts';

export function useInvoke(): InvokeResult {
  const [state, setState] = useState<InvokeState>('idle');
  const [output, setOutput] = useState<string | null>(null);
  const [paid, setPaid] = useState<PaidReceipt | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Detected in an effect (not during render) to avoid SSR hydration mismatches.
  const [needsWallet, setNeedsWallet] = useState(false);

  useEffect(() => {
    setNeedsWallet(typeof window !== 'undefined' && !window.ethereum);
  }, []);

  const invoke = useCallback(async (input: string) => {
    setError(null);
    setOutput(null);
    setPaid(null);
    setState('connecting');
    try {
      if (typeof window === 'undefined' || !window.ethereum) {
        setNeedsWallet(true);
        throw new Error('No wallet detected — install MetaMask (or any injected wallet) to pay.');
      }
      await ensureBaseSepolia();

      setState('paying');
      const { response, paid: receipt } = await payAndFetch(SKILL_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ input }),
      });

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
  }, []);

  return { state, output, paid, error, invoke, needsWallet };
}

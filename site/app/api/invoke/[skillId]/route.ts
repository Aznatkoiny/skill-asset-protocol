// THE COLLAR — serverless x402 seller gating a hosted skill.
//
// Port of the working seller reference at spikes/pi-wielder/src/x402-seller.mjs
// into a Next.js Node-runtime route handler. The flow, per the x402 v1 spec:
//
//   1. POST without X-PAYMENT  → 402 { x402Version: 1, accepts: [PaymentRequirements] }.
//   2. POST with X-PAYMENT     → facilitator /verify, then /settle. The settled
//      txHash is the single-use execution credential ("NO CREDENTIAL, NO RUN").
//   3. Only then does the skill run: the skill content (see ./skill-content.ts,
//      generated from ./skill.md) becomes the SYSTEM prompt of one Anthropic
//      Messages API call. The caller receives OUTPUT ONLY — never the skill text.
//
// NOTE we settle BEFORE executing the skill (same deliberate ordering as the
// reference seller): the txHash *is* the execution credential — pay → mint →
// consume → execute.
//
// REPLAY PROTECTION: the EIP-3009 nonce inside the signed TransferWithAuthorization
// is single-use ON-CHAIN. A replayed X-PAYMENT re-submits the same nonce, so the
// facilitator's /settle fails — settle-failure IS the replay rejection. The
// in-memory consumed-set below is belt-and-braces for a single warm serverless
// instance (instances don't share memory; the chain is the real guarantee).

import { NextResponse } from 'next/server';
import { SKILL_CONTENT } from './skill-content';

export const runtime = 'nodejs';

// --- x402 v1 / Base Sepolia constants (mirror x402-seller.mjs) ---------------
const X402_VERSION = 1;
const NETWORK = 'base-sepolia';
const USDC_ADDRESS = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const USDC_EIP712 = { name: 'USDC', version: '2' };
const USDC_DECIMALS = 6;

const PRICE_ATOMIC = '250000'; // $0.25 USDC (6 decimals)
const SPLIT = { creator: 0.24375, treasury: 0.00625 }; // 97.5 / 2.5 of $0.25

const KNOWN_SKILL_ID = 'optimizing-claude-code-prompts';
const DEFAULT_FACILITATOR = 'https://x402.org/facilitator';

const jsonToB64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64');
const b64ToJson = <T>(s: string): T => JSON.parse(Buffer.from(s, 'base64').toString('utf8')) as T;

// Per-instance consumed credentials (see REPLAY PROTECTION note above).
const consumed = new Set<string>();

interface PaymentRequirements {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  extra: { name: string; version: string };
}

async function postJson(url: string, body: unknown): Promise<unknown> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json().catch(() => null);
}

export async function POST(
  req: Request,
  ctx: { params: Promise<{ skillId: string }> },
) {
  const { skillId } = await ctx.params;
  if (skillId !== KNOWN_SKILL_ID) {
    return NextResponse.json({ error: `unknown skill: ${skillId}` }, { status: 404 });
  }

  // -- config: fail honestly BEFORE taking anyone's money -----------------------
  const payTo = process.env.PAY_TO_ADDRESS;
  if (!payTo) {
    return NextResponse.json(
      { error: 'seller misconfigured: PAY_TO_ADDRESS is not set' },
      { status: 500 },
    );
  }
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (!anthropicKey) {
    return NextResponse.json(
      { error: 'seller misconfigured: ANTHROPIC_API_KEY is not set' },
      { status: 502 },
    );
  }
  const facilitatorUrl = process.env.FACILITATOR_URL || DEFAULT_FACILITATOR;

  // -- input: validate before challenging (don't charge for an unrunnable call) --
  let input = '';
  try {
    const body = (await req.json()) as { input?: unknown };
    if (typeof body.input === 'string') input = body.input.trim();
  } catch {
    /* fall through to the 400 below */
  }
  if (!input) {
    return NextResponse.json(
      { error: 'request body must be JSON: { "input": "<your rough prompt>" }' },
      { status: 400 },
    );
  }

  const requirements: PaymentRequirements = {
    scheme: 'exact',
    network: NETWORK,
    maxAmountRequired: PRICE_ATOMIC, // atomic USDC (6 decimals) — $0.25
    resource: req.url,
    description: `Run the hosted skill "${KNOWN_SKILL_ID}" — output only, never the skill.`,
    mimeType: 'application/json',
    payTo,
    maxTimeoutSeconds: 60,
    asset: USDC_ADDRESS,
    // The buyer needs these to build the EIP-712 domain it signs against.
    extra: { name: USDC_EIP712.name, version: USDC_EIP712.version },
  };

  // -- step 1: no payment attached → challenge with 402 --------------------------
  const paymentHeader = req.headers.get('X-PAYMENT');
  if (!paymentHeader) {
    return NextResponse.json(
      { x402Version: X402_VERSION, error: 'X-PAYMENT header is required', accepts: [requirements] },
      { status: 402 },
    );
  }

  // -- step 2: decode + verify + settle through the facilitator -------------------
  let paymentPayload: unknown;
  try {
    paymentPayload = b64ToJson(paymentHeader);
  } catch {
    return NextResponse.json(
      { x402Version: X402_VERSION, error: 'malformed X-PAYMENT header', accepts: [requirements] },
      { status: 402 },
    );
  }

  const facilitatorBody = { x402Version: X402_VERSION, paymentPayload, paymentRequirements: requirements };

  let verify: { isValid?: boolean; invalidReason?: string } | null;
  let settle: { success?: boolean; errorReason?: string; transaction?: string; payer?: string } | null;
  try {
    verify = (await postJson(`${facilitatorUrl}/verify`, facilitatorBody)) as typeof verify;
    if (!verify?.isValid) {
      return NextResponse.json(
        {
          x402Version: X402_VERSION,
          error: `payment verification failed: ${verify?.invalidReason ?? 'unknown'}`,
          accepts: [requirements],
        },
        { status: 402 },
      );
    }

    settle = (await postJson(`${facilitatorUrl}/settle`, facilitatorBody)) as typeof settle;
  } catch {
    // Honest failure: the facilitator was unreachable — nothing was charged.
    return NextResponse.json(
      { error: `facilitator unreachable at ${facilitatorUrl} — payment not settled, nothing charged` },
      { status: 502 },
    );
  }

  if (!settle?.success || !settle.transaction) {
    // EIP-3009 nonces are single-use on-chain, so a replayed payment lands here:
    // settle-failure = replay rejected (or insufficient funds / expired authorization).
    return NextResponse.json(
      {
        x402Version: X402_VERSION,
        error: `payment settlement failed: ${settle?.errorReason ?? 'unknown'} (replayed or invalid authorization — EIP-3009 nonces spend exactly once)`,
        accepts: [requirements],
      },
      { status: 402 },
    );
  }

  // -- step 3: the settled txHash is a single-use credential ----------------------
  if (consumed.has(settle.transaction)) {
    return NextResponse.json(
      { error: 'replayed payment: credential already consumed', txHash: settle.transaction },
      { status: 409 },
    );
  }
  consumed.add(settle.transaction);

  // -- step 4: run the skill — output only, NEVER the skill text -------------------
  let output: string;
  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': anthropicKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1500,
        system: SKILL_CONTENT, // the protected asset stays server-side
        messages: [{ role: 'user', content: input }],
      }),
    });

    if (!anthropicRes.ok) {
      const detail = await anthropicRes.text().catch(() => '');
      // Honest failure: payment settled but the skill run failed. The txHash is
      // included so the buyer holds the receipt for the failed run.
      return NextResponse.json(
        {
          error: `skill execution failed: anthropic returned ${anthropicRes.status}`,
          detail: detail.slice(0, 500),
          paid: { amountUSDC: Number(PRICE_ATOMIC) / 10 ** USDC_DECIMALS, txHash: settle.transaction },
        },
        { status: 502 },
      );
    }

    const message = (await anthropicRes.json()) as {
      content?: Array<{ type: string; text?: string }>;
    };
    output = (message.content ?? [])
      .filter((b) => b.type === 'text' && typeof b.text === 'string')
      .map((b) => b.text)
      .join('\n');
  } catch {
    return NextResponse.json(
      {
        error: 'skill execution failed: anthropic unreachable',
        paid: { amountUSDC: Number(PRICE_ATOMIC) / 10 ** USDC_DECIMALS, txHash: settle.transaction },
      },
      { status: 502 },
    );
  }

  // -- success: output + receipt + declared split ----------------------------------
  return NextResponse.json(
    {
      output,
      paid: { amountUSDC: Number(PRICE_ATOMIC) / 10 ** USDC_DECIMALS, txHash: settle.transaction },
      split: SPLIT,
    },
    {
      headers: {
        // Standard buyer-visible settlement receipt (mirrors the reference seller).
        'X-PAYMENT-RESPONSE': jsonToB64({
          success: true,
          transaction: settle.transaction,
          network: NETWORK,
          payer: settle.payer,
        }),
      },
    },
  );
}

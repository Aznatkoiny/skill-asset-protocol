// pi-extension/x402.ts — makes Pi (@earendil-works/pi-coding-agent, v0.80.x)
// a Wielder without teaching it anything about payments.
//
// Install: copy this file into the project's `.pi/extensions/` (or
// `~/.pi/agent/extensions/`), run the paying proxy (`npm run proxy` plus
// collar + gateway, see RUNBOOK.md), then `/reload` inside pi.
//
// Note the shape of this extension: it points Pi at a localhost baseUrl and
// adds one HTTP tool and one display command. There is ZERO payment, wallet,
// or chain code here — Pi has no custom-fetch/retry hook, and it doesn't need
// one, because the paying proxy (src/proxy.mjs) answers every 402 upstream.
// That is ADR-0008: the Wielder is a wallet, not a harness. (Same pattern
// BlockRun's ClawRouter uses for OpenClaw on port 8402.)
//
// Written against the documented pi extension API (registerProvider /
// registerTool / registerCommand); exercised manually in the live demo — pi
// may not be installed in this environment, so nothing in the build depends
// on this file compiling.

const PROXY = process.env.PI_WIELDER_PROXY ?? "http://localhost:8402";

const displayUsdc = (amountAtomic: string) => {
  const padded = BigInt(amountAtomic).toString().padStart(7, "0");
  const value = `${padded.slice(0, -6)}.${padded.slice(-6)}`.replace(/0+$/, "").replace(/\.$/, "");
  return `$${value}`;
};

type SignedInvocationReceipt = {
  receipt: {
    quote: { amountAtomic: string };
    payment: { state: "settled" | "refunded"; txHash: string };
    execution: { state: "succeeded" | "failed" | "cancelled" };
    accounting: {
      allocationState: "finalized" | "pending_cogs_reconciliation";
      protocolFeeAtomic?: string;
      holderCredits: { recipientId: string; amountAtomic: string }[];
      ancestorCredits: { recipientId: string; amountAtomic: string }[];
    };
  };
  receiptHash: string;
  signature: string;
  algorithm: "Ed25519";
  keyId: string;
};

// Minimal structural type for the documented extension surface, so this file
// stands alone without pi's type package.
type Pi = {
  registerProvider(name: string, config: Record<string, unknown>): void;
  registerTool(tool: Record<string, unknown>): void;
  registerCommand(name: string, command: Record<string, unknown>): void;
  on?(event: string, handler: (...args: unknown[]) => unknown): void;
};

export default function activate(pi: Pi) {
  // --- one provider, two model families, one paying wallet behind it -------
  // Everything Pi sends to these models 402-pays per call through the proxy.
  pi.registerProvider("x402", {
    baseUrl: `${PROXY}/v1`,
    api: "openai-completions", // the proxy/gateway speak OpenAI chat-completions
    // pi requires an apiKey field when models are defined; the paying proxy
    // ignores Authorization entirely — payment IS the credential (ADR-0008).
    apiKey: "x402-payment-is-the-credential",
    models: [
      {
        id: "claude-sonnet-4-6",
        name: "claude via x402 (pay-per-call, Base Sepolia)",
        reasoning: false,
        input: ["text"],
        // pi tracks per-token cost; ours is flat per-call and lands on the
        // /ledger — zeros here so pi's meter doesn't double-count.
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 200_000,
        maxTokens: 8_192,
      },
      {
        id: "gpt-5.2",
        name: "gpt via x402 (pay-per-call, Base Sepolia)",
        reasoning: false,
        input: ["text"],
        // pi tracks per-token cost; ours is flat per-call and lands on the
        // /ledger — zeros here so pi's meter doesn't double-count.
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 128_000,
        maxTokens: 8_192,
      },
    ],
  });

  // --- the second asset class: a paid, hosted skill as a Pi tool -----------
  pi.registerTool({
    name: "invoke_skill",
    description:
      "Invoke the hosted, x402-paid skill 'optimizing-claude-code-prompts'. " +
      "Send a rough prompt/request as `input`; returns the optimized prompt. " +
      "Costs testnet USDC per call; the payment, royalty split, and ledger " +
      "entry are handled by the local paying proxy.",
    parameters: {
      type: "object",
      properties: {
        skillId: {
          type: "string",
          description: "Hosted skill id",
          default: "optimizing-claude-code-prompts",
        },
        input: { type: "string", description: "The rough request to optimize" },
      },
      required: ["input"],
    },
    async execute(args: { skillId?: string; input: string }) {
      const skillId = args.skillId ?? "optimizing-claude-code-prompts";
      const res = await fetch(`${PROXY}/invoke/${skillId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ input: args.input }),
      });
      if (!res.ok) return `invoke_skill failed (HTTP ${res.status}): ${await res.text()}`;
      const { output, receipt } = (await res.json()) as {
        output: string;
        receipt: SignedInvocationReceipt;
      };
      const invocation = receipt.receipt;
      const accounting = invocation.accounting;
      const claims = accounting.allocationState === "finalized" && accounting.protocolFeeAtomic
        ? [
            ...accounting.holderCredits.map((credit) => `${credit.recipientId} ${displayUsdc(credit.amountAtomic)}`),
            ...accounting.ancestorCredits.map((credit) => `${credit.recipientId} ${displayUsdc(credit.amountAtomic)}`),
            `treasury ${displayUsdc(accounting.protocolFeeAtomic)}`,
          ].join(" / ")
        : "full gross held for accounting reconciliation";
      return `${output}\n\n[${invocation.execution.state} · paid ${displayUsdc(invocation.quote.amountAtomic)} · tx ${invocation.payment.txHash.slice(0, 10)}… · ${claims} · receipt ${receipt.receiptHash.slice(0, 10)}…]`;
    },
  });

  // --- /ledger: the unified session meter, rendered by the proxy -----------
  pi.registerCommand("ledger", {
    description: "Show this session's local x402 receipt view (inference + Skills)",
    async handler() {
      const res = await fetch(`${PROXY}/ledger`);
      return res.ok ? await res.text() : `ledger unavailable (HTTP ${res.status}) — is the proxy running?`;
    },
  });
}

# RUNBOOK — testnet run & live Pi demo

Everything in [README.md](./README.md) up to `npm run e2e` is fully offline.
This runbook covers the two things that are **manual by design**: funding a
testnet wallet, and installing Pi with the extension for the live demo.

## 1. Create and fund the Wielder wallet (Base Sepolia — manual)

1. Generate a throwaway key (never reuse a real one):

   ```bash
   node -e "import('viem/accounts').then(m => { const pk = m.generatePrivateKey(); console.log('PRIVATE_KEY=' + pk); console.log('address:', m.privateKeyToAccount(pk).address); })"
   ```

2. `cp .env.example .env`, paste the `PRIVATE_KEY`, and set `PAY_TO_ADDRESS`
   to a second address you control (that's where the sellers receive USDC —
   generate one the same way if needed). **Never commit `.env`.**

3. Fund the Wielder address from the **Coinbase CDP faucet**
   (<https://portal.cdp.coinbase.com/products/faucet>, free, requires a CDP
   account):
   - network **Base Sepolia**, asset **USDC** → request (typically 10 USDC/day);
   - network **Base Sepolia**, asset **ETH** → request a small amount.
     (EIP-3009 settlement is facilitator-sponsored, so the buyer mostly needs
     USDC; the ETH covers you if you later broadcast anything yourself.)

4. Sanity-check the balance on <https://sepolia.basescan.org> (search the
   address; USDC contract `0x036CbD53842c5426634e7929541eC2318f3dCF7e`).

## 2. Testnet run (real facilitator, real model APIs)

In `.env`: unset the mocks and add model keys —

```bash
MOCK_FACILITATOR=0
MOCK_LLM=0
FACILITATOR_URL=https://x402.org/facilitator   # free, no-auth, Base Sepolia
ANTHROPIC_API_KEY=sk-ant-…
OPENAI_API_KEY=sk-…
```

Three terminals (or background them), sellers first:

```bash
set -a; source .env; set +a       # in each terminal
npm run collar                     # :8404 — hosted skill behind the collar
npm run gateway                    # :8403 — 402-gated inference reseller
npm run proxy                      # :8402 — THE WIELDER (paying proxy)
```

Exercise all three legs through the proxy only:

```bash
curl -s localhost:8402/v1/chat/completions -H 'content-type: application/json' \
  -H 'x-session-label: plan' \
  -d '{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"Plan a refactor of the settlement engine tests."}]}'

curl -s localhost:8402/v1/chat/completions -H 'content-type: application/json' \
  -H 'x-session-label: implement' \
  -d '{"model":"gpt-5.2","messages":[{"role":"user","content":"Implement the plan."}]}'
  # use any chat model your OpenAI key can access

curl -s localhost:8402/invoke/optimizing-claude-code-prompts \
  -H 'content-type: application/json' -d '{"input":"make the checkout page faster"}'

curl -s localhost:8402/ledger        # the unified session ledger
```

Each response carries `x-wielder-overhead` (402 roundtrip + sign +
facilitator verify/settle, in ms) — these are the **real** payment-overhead
numbers to feed back into the PRD's demand-side section, and every settled
txHash is checkable on <https://sepolia.basescan.org>.

Replay check on testnet: re-sending a captured `X-PAYMENT` header fails at
the facilitator (the EIP-3009 nonce is already used on-chain) or, if it were
somehow re-settled, at the collar's consumed-set (HTTP 409).

## 3. Live Pi demo (manual — pi is not installed by this spike)

1. Install Pi (v0.80.x): `npm install -g @earendil-works/pi-coding-agent`
2. Install the extension into the project you'll demo from:

   ```bash
   mkdir -p .pi/extensions
   cp <this-repo>/spikes/pi-wielder/pi-extension/x402.ts .pi/extensions/
   ```

   (or `~/.pi/agent/extensions/` for a global install). If the proxy is not
   on the default port, export `PI_WIELDER_PROXY=http://localhost:<port>`.
3. With collar + gateway + proxy running (section 2), start `pi` in that
   project and `/reload` to pick up the extension. Verify against pi's docs
   that the `registerProvider` config fields (`api`, model entries) match
   your installed version — the extension is written against the documented
   v0.80.x API but is exercised manually, not in CI.
4. Demo script ("Claude plans, GPT implements, one skill invocation"):
   - select the `x402` provider's claude model → ask for a plan;
   - switch to the gpt model → ask it to implement;
   - have Pi call the `invoke_skill` tool (e.g. "optimize this prompt: …");
   - run `/ledger` → one wallet, three payees, unified attributed ledger.

## What stays manual, on purpose

- CDP faucet funding (no faucet automation — ToS and flakiness).
- Pi installation and the extension smoke-test (pi may not exist in CI).
- Feeding the measured testnet overhead numbers back into the PRD.

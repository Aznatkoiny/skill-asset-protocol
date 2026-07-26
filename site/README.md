# Skill Asset Protocol site

The site has two deliberately separate paths:

- `/` is the employer-facing product preview and deterministic attribution
  sandbox. It needs no account, wallet, API key, network call, or payment.
- `/proof` preserves the original manifesto and optional Base Sepolia x402
  invocation proof.

## Local product preview

Use Node 22. The production dependency graph and image optimizer are verified
against that major.

```bash
npm ci
npm run dev
```

Open <http://localhost:3000>. The full seeded sandbox works with no environment
file and never calls the payment or model API.

The sample organization, people, Invocations, outcome evidence, and provisional
reward are fictional. Refreshing or choosing **Restart sandbox** returns to the
same deterministic fixture.

## Optional configuration

Copy the template only when you need to change the pilot CTA or operate the
testnet proof:

```bash
cp .env.example .env.local
```

| Variable | Required for `/` | Required for paid `/proof` invocation |
|---|---:|---:|
| `NEXT_PUBLIC_PILOT_CONTACT_URL` | No | No |
| `ENABLE_PAID_PROOF=true` | No | Yes |
| `PAY_TO_ADDRESS` | No | Yes |
| `ANTHROPIC_API_KEY` | No | Yes |
| `FACILITATOR_URL` | No | No (testnet default provided) |

The proof path uses testnet USDC only. Use a throwaway testnet wallet and never
put a wallet private key in the site environment. Paid proof invocation is
disabled by default because free testnet funds can still trigger real model
spend. Keep it disabled until the deployment has persistent rate limiting and
an Anthropic spend cap.

## Verification

```bash
npm test
npm run lint
npm run build
npm audit --omit=dev
```

`npm test` covers the sandbox fixture and transition guards with Node's built-in
test runner. The build must pass without secrets because `/` is an offline
product preview; the proof API validates its seller configuration at request
time. The production audit is expected to report zero vulnerabilities. See the
[dependency security audit](../docs/dependency-security-audit.md) for the
remaining dev-only advisory and the intentionally pinned transitive fixes.

## Relevant files

| Path | Role |
|---|---|
| `app/page.tsx` | Employer-facing landing page composition |
| `app/landing.module.css` | Industrial product-page design system |
| `app/components/landing/AttributionSandbox.tsx` | Client-only sandbox UI |
| `app/components/landing/sandbox-model.ts` | Deterministic fixture and reducer |
| `app/components/InvokeControls.tsx` | Wallet/invocation client island on `/proof` |
| `app/proof/page.tsx` | Preserved manifesto and x402 proof route |
| `app/api/invoke/[skillId]/route.ts` | Optional testnet Collar endpoint |

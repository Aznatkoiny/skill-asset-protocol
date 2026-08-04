# Skill Asset Protocol site

**Release status:** pre-release candidate. The approved design's implementation
and fresh-evidence gate is not cleared; do not deploy this candidate as the
public homepage yet.

The site has two deliberately separate paths:

- `/` is the wallet-native **Agent Spend Control Plane** preview and
  deterministic **Wallet Kernel** sandbox. It needs no account, wallet, API
  key, network call, payment, or saved data.
- `/proof` preserves the original manifesto, one bounded historical Base
  Sepolia receipt, and the retired x402 invocation experiment as a static
  archive. The site exposes no wallet connection or paid endpoint.

The approved v1 product is a customer-hosted Wallet Kernel for spending policy,
exact human approval, signed receipts, and reconciliation. The employer Skill
attribution and reward experience remains in the repository as deferred
expansion research; it is not linked from the current homepage and does not set
the v1 interface. See the
[approved design](../docs/superpowers/specs/2026-07-31-agent-spend-control-plane-design.md).

## Local product preview

Use Node 22. The production dependency graph and image optimizer are verified
against that major.

```bash
npm ci
npm run dev
```

Open <http://localhost:3000>. The full seeded sandbox works with no environment
file and never calls the payment or model API.

The sample Agent, customer-owned wallet, policy, Spend Intents, decisions,
approval, and receipt projection are fictional. The sandbox never creates a
wallet payment signature or broadcasts a transaction. Refreshing or choosing
**Restart sandbox** returns to the same deterministic fixture.

## Optional configuration

Copy the template only when you need to change the Wallet Kernel pilot CTA:

```bash
cp .env.example .env.local
```

| Variable | Required | Purpose |
|---|---:|---|
| `NEXT_PUBLIC_PILOT_CONTACT_URL` | No | Override the design-partner CTA destination |

Never put a wallet key, facilitator credential, or model-provider secret in the
site environment. The customer-hosted Wallet Kernel—not the website—owns any
future payment integration.

The historical receipt is evidence only that one test-USDC transfer settled on
Base Sepolia. It does not prove that the endpoint is currently live, that model
execution succeeded, that a declared split occurred, that customer demand
exists, or that the Wallet Kernel is production-ready. The offline homepage
sandbox is illustrative, not live settlement evidence.

## Verification

```bash
npm test
npm run lint
npm run build
npm audit --omit=dev
```

`npm test` covers the spend-control sandbox and public-claim quarantine with
Node's built-in test runner. The build must pass
without secrets because both routes are static product/research surfaces. The
final-head production audit must report zero vulnerabilities before merge. See the
[dependency security audit](../docs/dependency-security-audit.md) for the prior
audit record, the remaining dev-only advisory, and the intentionally pinned
transitive fixes.

## Relevant files

| Path | Role |
|---|---|
| `app/page.tsx` | Wallet-native Agent Spend Control landing page |
| `app/landing.module.css` | Industrial product-page design system |
| `app/components/landing/SpendControlSandbox.tsx` | Current client-only Wallet Kernel sandbox |
| `app/components/landing/spend-control-model.ts` | Deterministic spend-policy fixture and reducer |
| `app/proof/page.tsx` | Static archive with one bounded historical receipt |

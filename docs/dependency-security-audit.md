# Dependency security audit

Date: 2026-07-26

Scope: the Next.js application in `site/`, including production and development
dependencies, the image optimizer path, and deployment-adjacent server code.

## Executive summary

- The original install reported 12 high-severity findings.
- `npm audit --omit=dev` now reports **0 vulnerabilities**.
- The full development tree reports 9 high-severity package entries. They all
  trace to one `brace-expansion` denial-of-service advisory in the ESLint tool
  chain, not nine independent defects.
- `npm audit fix --force` was rejected because npm proposes incompatible major
  changes and invalid historical downgrades of the Next.js lint configuration.

The remaining advisory is not reachable from the deployed application. It is
used by local lint glob matching over trusted repository configuration. Keep it
visible in CI and update when the ESLint/Next dependency chain publishes a
compatible release.

## Remediation applied

| Dependency | Before | After | Reason |
|---|---:|---:|---|
| `next` | 15.5.20 | 15.5.22 | Clears the direct Next.js advisories while staying on the existing release line. |
| `eslint-config-next` | 15.5.20 | 15.5.22 | Keeps framework and lint configuration aligned. |
| `postcss` | vulnerable transitive | 8.5.23 override | Pulls the patched same-major parser into the production tree. |
| `sharp` | 0.34.5 transitive | 0.35.3 override | Pulls the patched image processor; requires Node 20.9 or newer. |
| `brace-expansion` | 5.0.7 where compatible | 5.0.8 | Clears patched modern dependency paths. |

The project pins Node `22.x` so local and Vercel builds use the same supported
major and satisfy Sharp's runtime requirement.

The PostCSS and Sharp overrides are temporary compatibility controls. Remove
them when the selected Next.js release declares patched versions directly.
Sharp 0.35 is outside Next 15.5.22's declared `^0.34.3` range, so it received an
explicit build, runtime, and image-optimization smoke test before release.

## Residual development advisory

Advisory:
[GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg),
unbounded brace expansion causing an out-of-memory denial of service.

Observed path: legacy `brace-expansion` 1.x through `minimatch` 3.x in ESLint,
`@eslint/eslintrc`, and plugins bundled by `eslint-config-next`. There is no
patched 1.x release. npm's forced proposals either downgrade core lint packages
to unrelated historical versions or cross unsupported major boundaries.

Risk acceptance:

- Development-only; absent from `npm audit --omit=dev`.
- Input is repository-owned lint configuration and file patterns, not an
  untrusted network request.
- Linting should still run in a bounded CI job.
- Recheck on every dependency update and at least monthly while active.

## Server safeguards added during review

- The paid `/proof` invocation endpoint is disabled unless
  `ENABLE_PAID_PROOF=true` is set explicitly.
- Request bodies are capped at 16 KiB and prompt input at 4,000 characters.
- Facilitator and model calls have abort deadlines; the route has an explicit
  60-second maximum duration.
- `PAY_TO_ADDRESS` must be a nonzero 20-byte EVM address.
- Global responses disable the framework signature and add CSP frame/base/object
  restrictions, clickjacking protection, MIME sniffing protection, a strict
  referrer policy, and a restrictive permissions policy.

Do not enable paid proof on a public deployment until persistent rate limits and
an Anthropic account-level spend cap are configured. Free testnet USDC can still
trigger real model cost.

## Verification record

- `npm test`: 6/6 passing.
- `npm run lint`: passing.
- Clean `npm run build`: passing in an isolated copy to avoid the active local
  development server rewriting `.next` concurrently.
- Production start smoke test: passing.
- Next image optimizer request for `/icon.png` at 64 px: HTTP 200, `image/png`.
- `npm audit --omit=dev`: 0 vulnerabilities.
- Full `npm audit`: 9 high package entries, all from the single dev-only advisory
  described above.

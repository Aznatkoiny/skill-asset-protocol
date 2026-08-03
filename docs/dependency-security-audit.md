# Dependency security audit

- Original dependency audit: 2026-07-26
- Updated for the spend-control site revision: 2026-08-02

Scope: the Next.js application in `site/`, including production and development
dependencies, the image optimizer path, and deployment-adjacent server code.

## Executive summary

- The 2026-07-26 install reported 12 high-severity findings before remediation.
- At that verified dependency snapshot, `npm audit --omit=dev` reported **0
  vulnerabilities**.
- At that snapshot, the full development tree reported 9 high-severity package
  entries. They all traced to one `brace-expansion` denial-of-service advisory
  in the ESLint tool chain, not nine independent defects.
- `npm audit fix --force` was rejected because npm proposes incompatible major
  changes and invalid historical downgrades of the Next.js lint configuration.

Those dependency-audit results are a historical verification record. The
current PR refreshed the lockfile on 2026-08-02 and now resolves the legacy
`brace-expansion` path to patched 1.1.18 and the modern path to patched 5.0.9.
The clean install reported zero vulnerabilities. Fresh tests and lint pass;
the normal-environment production build and full audit also pass at the current
pre-merge head. Final merged-head CI remains a release gate.

## Remediation applied

| Dependency | Before | After | Reason |
|---|---:|---:|---|
| `next` | 15.5.20 | 15.5.22 | Clears the direct Next.js advisories while staying on the existing release line. |
| `eslint-config-next` | 15.5.20 | 15.5.22 | Keeps framework and lint configuration aligned. |
| `postcss` | vulnerable transitive | 8.5.23 override | Pulls the patched same-major parser into the production tree. |
| `sharp` | 0.34.5 transitive | 0.35.3 override | Pulls the patched image processor; requires Node 20.9 or newer. |
| `brace-expansion` | 1.1.16 and 5.0.8 | 1.1.18 and 5.0.9 | Clears the high-severity development-only denial-of-service advisory on both dependency paths. |

The project requires Node `22.x` so local and Vercel builds use the same
supported major and satisfy Sharp's runtime requirement. CI pins
[Node 22.23.2](https://nodejs.org/en/blog/release/v22.23.2), the Node 22 LTS
security release published on 2026-07-29.

The PostCSS and Sharp overrides are temporary compatibility controls. Remove
them when the selected Next.js release declares patched versions directly.
Sharp 0.35 is outside Next 15.5.22's declared `^0.34.3` range, so it received an
explicit build, runtime, and image-optimization smoke test before release.

## Resolved development advisory

Advisory:
[GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg),
unbounded brace expansion causing an out-of-memory denial of service.

Observed path: legacy `brace-expansion` 1.x through `minimatch` 3.x in ESLint,
`@eslint/eslintrc`, and plugins bundled by `eslint-config-next`. The advisory
was updated to identify patched 1.1.17; the refreshed lockfile resolves 1.1.18.
The modern nested path also advanced from 5.0.8 to 5.0.9. No forced downgrade,
unsupported major change, or direct dependency was introduced.

## Website attack-surface reduction during review

- The hosted Skill seller API, browser-wallet client, and payment-enablement
  environment variables were removed. The website has no signing, facilitator,
  transaction-broadcast, or model-provider path.
- `/proof` is a static archive separated from the Wallet Kernel candidate. Its
  single historical Base Sepolia receipt is bounded evidence, not proof of a
  currently live endpoint, successful model execution, a completed split,
  customer demand, or production readiness.
- The archived manifesto explicitly says that the historical interface did not
  directly return the Skill file while model output can still leak or enable
  reconstruction. It makes no categorical extraction-resistance claim.
- The spend-control sandbox is an offline deterministic state machine. It uses
  no account, wallet, key, signature, network call, payment, saved data, or raw
  prompt and labels its final artifact as an unsigned session projection.
- Global responses disable the framework signature and add CSP frame/base/object
  restrictions, clickjacking protection, MIME sniffing protection, a strict
  referrer policy, and a restrictive permissions policy.

## Verification records

Current PR, 2026-08-02:

- User-run `npm ci`: 325 packages installed; install-time audit reported 0
  vulnerabilities.
- `npm test`: 24/24 passing. This dependency-free suite covers the Wallet
  Kernel allow/deny/approval/retry sandbox, unsigned projection boundaries, the
  default-deny path, safe-integer atomic-money conservation, and public-claim
  quarantine across the website and READMEs.
- `npm run lint`: passing under Node 22.22.0 in the agent environment.
- User-run `npm run build` under Node 22.22.0: passing; Next.js 15.5.22
  compiled, checked types, generated all static pages, and emitted `/`,
  `/_not-found`, `/icon.png`, and `/proof`.
- User-run `npm audit --audit-level=high`: 0 vulnerabilities.
- `.github/workflows/site.yml` now runs locked install, tests, lint, production
  build, and a high/critical full-tree dependency audit for every pull request
  that changes `site/**`, the root `README.md` scanned by the claim-quarantine
  test, or the workflow itself. It uses immutable action pins and Node 22.23.2.
- The CI audit command is `npm audit --audit-level=high`: high and critical
  advisories in production or development dependencies fail the job; low and
  moderate advisories remain visible without failing this gate.
- The sandboxed Turbopack build reached optimization but could not bind its
  local helper port (`EPERM`); the same command passed in the user's normal
  environment. Production start, image optimization, and final merged-head CI
  remain **pending final-head verification**.

Previous dependency snapshot, 2026-07-26:

- `npm test`: 6/6 passing.
- `npm run lint`: passing.
- Clean `npm run build`: passing in an isolated copy to avoid the active local
  development server rewriting `.next` concurrently.
- Production start smoke test: passing.
- Next image optimizer request for `/icon.png` at 64 px: HTTP 200, `image/png`.
- `npm audit --omit=dev`: 0 vulnerabilities.
- Full `npm audit`: 9 high package entries, all from the single dev-only advisory
  described above.

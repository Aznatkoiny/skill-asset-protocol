# Human Choice website

**Publication status:** live on Vercel at <https://neverhandedover.com> since
2026-09-06. The owner approved the Human Choice rebrand after reviewing the
private site and authorized the public deployment.
Wallet Kernel remains an offline prototype with its live-product acceptance
requirements in effect. See the [publication decision](../docs/strategy/2026-09-06-human-flourishing-direction.md#publication-decision)
and [website review](../docs/reviews/2026-09-06-human-choice-website.md) for deployment results.

Human Choice is the project owner's selected umbrella identity. The mission,
principles, English copy, and design were developed for this project. See the
[agreed direction](../docs/strategy/2026-09-06-human-flourishing-direction.md).

## Pages

| Route | Purpose |
| --- | --- |
| `/` | Human flourishing mission, a labeled time thought experiment, commitments, and a concrete system |
| `/principles` | Capability, agency, participation, tradeoffs, and evidence commitments |
| `/research` | Four proposed research questions, with visible status |
| `/research/[slug]` | Why the question matters, hypothesis, method outline, outcomes, and reconsideration criteria |
| `/systems` | Wallet Kernel, the deterministic sandbox, bounded engineering evidence, and live-use limits |
| `/about` | Purpose, project history, working methods, and links to public discussion |
| `/proof` | Original manifesto and historical receipt preserved as a static archive; no live payment endpoint |

## Run locally

Use Node 22. The site uses system fonts and needs no font service, account,
wallet, API key, or environment file.

```bash
npm ci
npm run dev
```

Open <http://localhost:3000>. All reading routes are statically rendered.
The homepage thought experiment and the Systems sandbox are client components.
The sandbox has no payment or model API integration. Reloading or choosing
**Restart sandbox** restores the deterministic fixture.

## Evidence and research

Research outlines are proposed studies, with no participant results. The
homepage's two-hour scenario illustrates the mission and is not a measured
benefit. The Systems page links the retained installed offline evidence at a
fixed repository revision and identifies its synthetic external providers.
CDP/testnet use and human outcomes remain unvalidated.

The historical test-USDC receipt supports one bounded transfer. It does not
prove current endpoint behavior, useful output, royalties, demand, or
production readiness. Follow the [evidence precedence](../docs/evidence-precedence.md)
and [approved product design](../docs/superpowers/specs/2026-07-31-agent-spend-control-plane-design.md).

## Configuration

`NEXT_PUBLIC_PILOT_CONTACT_URL` optionally changes the GitHub pilot link at the
end of the Systems demonstration. It is a destination link; the website does
not contact anyone or collect form submissions. Wallet credentials remain
outside the website.

Metadata retains the existing `neverhandedover.com` domain. Each page has its
own canonical path. The Human Choice name does not imply a new domain has
been acquired or connected.

## Verification

```bash
npm test
npm run lint
npm run build
npm audit --omit=dev
```

The existing sandbox tests cover authority, approval, retry, and the distinction
between a browser projection and settlement evidence. The production dependency
audit must report zero vulnerabilities before merge. Browser review should
cover the homepage choices, all navigation and study routes, mobile layout,
keyboard access, the complete sandbox flow, and reset.

## Main files

- `app/human-choice-content.ts`: commitments, proposed questions, and pinned evidence links.
- `app/human-choice.module.css`: shared editorial design and responsive layouts.
- `app/components/human-choice/`: site frame and the time thought experiment.
- `app/components/landing/SpendControlSandbox.tsx`: existing deterministic Wallet Kernel sandbox.
- `app/manifesto.tsx` and `app/content.ts`: historical archive presentation and content.

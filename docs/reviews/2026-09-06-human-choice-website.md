# Human Choice website implementation

Implemented 2026-09-06 in the working tree on `codex/human-choice-website`,
based on `4b2717b94c47151a26c8e70cbe5806aa5bfd277b`.

## Result

The owner selected Human Choice and explicitly directed the project to proceed
after reviewing existing uses of the name. The website now presents the
project's own mission, principles, proposed research, and Wallet Kernel work.
See the [agreed direction](../strategy/2026-09-06-human-flourishing-direction.md).

The candidate has ten content routes: Home, Principles, Research, four research
questions, Systems, About, and the historical proof archive. It uses warm paper,
dark green ink, serif headings, an original arch mark, and system fonts. The
homepage's interactive time scenario is explicitly a thought experiment.

Research outlines identify their hypotheses, comparisons, intended outcomes,
reconsideration criteria, and proposed status. The Systems page preserves the
existing deterministic sandbox and links installed offline evidence at a fixed
revision. The archive keeps its historical identity and gains a Human Choice
return link.

The sandbox now focuses its status heading only when its stage changes. This
prevents development Strict Mode from skipping the Systems introduction on
initial page entry while retaining announcements after user actions.

## Verification

- All 27 existing sandbox and public-claim checks passed on the final source.
  `npm test` passed; direct execution with
  `node --experimental-strip-types app/components/landing/spend-control-model.test.mjs`
  also displayed all 27 individual results. The restricted runner's `--test`
  output summarized only the test file, so that output alone was not used for
  the individual-check count.
- ESLint passed. The final production build passed compilation, lint, type
  checking, and static generation of all routes.
- Production dependency audit: zero reported vulnerabilities after pinning the
  existing transitive `nanoid` dependency from 3.3.16 to 3.3.18. The lockfile
  changes only that package. See the
  [upstream advisory](https://github.com/advisories/GHSA-2v37-7h3g-55p8).
- All ten rendered content pages have one h1, a Human Choice document title,
  and the correct canonical URL. All 111 internal links and anchors resolve.
- All 31 local links in the affected orientation and direction documents resolve.
- Browser review covered desktop and mobile layouts, navigation, a complete
  research question, proposed-study labels, and the full sandbox flow:
  load policy, allow, deny, queue approval, approve, deliberately retry, inspect
  the unsigned projection, and reset.
- At a 390px viewport override, measured content width was 375px; Home, About,
  a research question, and Systems (including the completed projection) had no
  horizontal overflow. The override was reset after testing.
- The time illustration responded to pointer input and keyboard Tab/Space.
  A fresh production-page check reported no new browser warnings or errors.
- `git diff --check` passed.

The first production build stalled in the restricted process environment and
was stopped. The subsequent and final builds completed with permission for
the normal Next.js build workers.

## Review and scope

The production preview is served locally at <http://127.0.0.1:4117>. Run it
again from `site/` with `npm run build` followed by
`npm run start -- --hostname 127.0.0.1 --port 4117`.

These are uncommitted local changes in an isolated worktree. No public site
deployment or domain change was performed. The existing product release
requirements remain explicit on the Systems page; this website work supplies
no new live-payment, demand, or human-outcome evidence.

## Private remote review

The user could not reach localhost from their phone and said Vercel was not
an option. A separate owner-only Sites deployment now provides the review at
<https://human-choice-review.aznatkoiny.chatgpt.site>.

- Hosting status: succeeded, 2026-09-06. The HTTPS address opens the expected
  ChatGPT sign-in screen. The owner must use the same account to view it;
  authenticated remote page rendering was not checked in the browser.
- Source checkout: `/tmp/human-choice-sites-preview-20260906`.
- Source commit: `8e08131923d31cb80c7b17486e490d06154f7b68`.
- Sites project: `appgprj_6a9dc41aabf48191aa3b8471ff37c2ad`.
- Saved version: 1,
  `appgprj_6a9dc41aabf48191aa3b8471ff37c2ad~appgver_0455193ad40c81918862b6e6a3d119d0`.
- Deployment: `appgdep_6a9dc4c48bbc8191a99cd65c816c2a71`.

The standalone source contains the same pages, styles, and interactions as
the verified implementation. Preview adaptations enable Next.js static
export, use the host-provided pre-publication origin in metadata, discourage
indexing, and supply static response headers. The static production build
passed compilation, lint, type checks, and generation. Its validated archive
contains 56 files, including all ten content pages and a 404 page. The exact
source was pushed to the private Sites repository before the version was saved.

At the private-review stage, the project's GitHub branch was still uncommitted
and the public website had not been replaced. Sites calls this a production deployment of a
separate private site; it is a review copy of the proposed website.

## Vercel publication preparation

After reviewing the private website, the owner approved Human Choice as the
rebrand and explicitly authorized publication on Vercel. The publication
decision is recorded in the [strategy](../strategy/2026-09-06-human-flourishing-direction.md#publication-decision).
The accepted website is being deployed to the existing project
`prj_5nsKttcQVAI3HqlDvJbSnG5Xsqz4`, owned by `antonys-projects-d94f821f`.

The configured production domains are `neverhandedover.com`,
`www.neverhandedover.com`, `skillassetprotocol.com`, and
`skill-asset-protocol.vercel.app`. Canonical metadata uses
`https://neverhandedover.com`. The prior production deployment is
`dpl_E6z7rZnCSo5hUihFbnhhwUvD9bbd`, retained as a rollback candidate.

One publication-specific wording change makes the Systems status precise:
“Wallet Kernel is not released for live use.” It replaces the website's
pre-publication notice while preserving the offline evidence and live-use
limits. No other page design or interaction changed after the private review.

Final checks passed: all 27 sandbox and public-claim checks; compilation, lint,
types, and static generation in the production build; zero production
dependency vulnerabilities; and `git diff --check`. Vercel's dry deployment
inspection identified 42 website source files and excluded `.next`, `.vercel`,
and `node_modules`. No local wallet or provider credentials are included.

## Vercel publication result

Production deployment succeeded on 2026-09-06. Vercel reports **Ready** and
has assigned the existing public domains to Human Choice.

- Main address: <https://neverhandedover.com>.
- Deployment URL: <https://skill-asset-protocol-53o6a1faf-antonys-projects-d94f821f.vercel.app>.
- Deployment ID: `dpl_3N5CAndNhtrnKCWrQE5Ja31Q2bhy`.
- Published website source: `e2a22f3f090ac5f117973579d84ba69d711564e1` on
  `codex/human-choice-website`, pushed to the project's GitHub repository.
- Alias status: Vercel confirms `neverhandedover.com`,
  `www.neverhandedover.com`, `skillassetprotocol.com`,
  `skill-asset-protocol.vercel.app`, and the existing team project alias.

Browser verification on the public domain showed the Human Choice homepage
without an authentication prompt. The Rest choice changed its explanation;
navigation to Systems displayed the offline sandbox and the live-use release
limit. The meaningful-delegation research page rendered its proposed-study
status, method, outcomes, and reconsideration criteria. This supplements the
full local browser checks above; it is not a new human or payment study.

The final follow-up commit records publication results in documentation only.
It does not change the deployed application. The website branch is pushed;
this publication does not merge the branch into the repository's default branch.

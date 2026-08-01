---
name: optimizing-claude-code-prompts
description: Turn a rough or vague request to Claude Code into a precise, repo-grounded, high-performing prompt. Use when the user wants help phrasing, drafting, improving, optimizing, tightening, or "making better" a prompt/request/instruction for Claude Code; when the user pastes a draft and asks how to word it; when a prompt already ran and Claude did the wrong thing (diagnose and fix it); or when Claude Code keeps missing the mark — doing too much, ignoring constraints, solving the wrong problem, over-engineering, or needing many back-and-forth rounds. Triggers include "optimize this prompt", "help me ask Claude to…", "rewrite my request", "why did Claude do that", "how should I word this", "make this prompt clearer".
---

# Optimizing Claude Code Prompts

## Overview

Rewrite a user's rough request into a prompt that Claude Code can execute correctly on the
first pass. The current models (Opus 4.8) follow instructions **literally** and run
**autonomously**, so the highest-leverage move is to front-load intent, constraints, and a
runnable check in the first message. Vague asks spread across many turns waste tokens and
build the wrong thing.

**Core principle:** A strong Claude Code prompt names the **goal**, the **context**, the
**constraints**, the **files/patterns to follow**, and **a check Claude can run to know it's
done**. Optimizing means supplying whichever of these the user left out — and resolving each
to a *real artifact in this repo*, not a placeholder the user must fill in later.

## The one rule that makes this skill worth invoking: ground in the repo

A prompt full of `@[your-file-here]` and "run the test suite" is just a template — it hands the
hard part back to the user. Before writing the optimized prompt, **resolve every reference to a
real thing** using the tools you have:

| Reference | How to resolve it | Don't emit |
|---|---|---|
| The target file(s) | `Glob`/`Grep` for the actual path | `@[src/whatever]` |
| "Done when…" check | Read `package.json` scripts / `Makefile` / `pyproject.toml` / CI config for the real test/build/lint command | "run the tests" |
| "Follow the pattern in…" | `Grep` for a sibling that already does the thing; name that file | "the existing pattern" |
| The symptom's likely location | `Grep` the error string / feature name to the directory | "somewhere in the code" |

**Resolve, don't guess.** If a genuine look can't resolve something, ask **one** surgical
question — never paper over it with a bracketed guess.

**Red flags that you skipped grounding** (STOP and go look): the output prompt contains `[...]`,
"the relevant file", "your test command", "the appropriate", or any path you didn't verify exists.

## Pick the mode

| The user… | Mode | What you do |
|---|---|---|
| Pasted a draft prompt | **Optimize** | Ground it, fill missing ingredients, return the rewrite |
| Gave a bare goal ("add auth") | **Generate** | Ground it, build the prompt from scratch |
| Says a prompt already failed ("Claude did X not Y") | **Diagnose** | Map the failure to the missing ingredient, fix it, add the session-hygiene step |
| Wants a large/multi-file feature | **Spec** | Don't hand-write a mega-prompt — route to the interview→SPEC.md pattern (see reference) |

## Workflow

1. **Capture** the raw request verbatim. Pick the mode.
2. **Ground** in the repo — resolve real paths, the real verification command, the real pattern
   file (table above). Do this with parallel `Glob`/`Grep`/`Read` calls; it's fast and it's the
   whole point.
3. **Diagnose + score** the request against the seven ingredients. Show the scorecard.
4. **Resolve gaps:** correctness-blocking gaps that grounding couldn't settle → up to **3**
   `AskUserQuestion` questions. If the user wants speed ("just optimize it"), proceed and label
   any remaining assumption explicitly.
5. **Write** the optimized prompt as a copy-paste block, with real values throughout.
6. **Hand back + offer to run it.** Note the one assumption most worth confirming, if any.

Don't pad the prompt with obvious instructions ("write clean code"). Opus 4.8 is literal and
smart — filler dilutes the real constraints.

## The seven ingredients

| Ingredient | Answers | Weak → Strong |
|---|---|---|
| **Goal** | What outcome, concretely? | "improve the dashboard" → "add date-range filtering to the dashboard" |
| **Context** | Why / where does this live? | — → "endpoint is `@src/api/orders.ts`; read-heavy, data changes hourly" |
| **Constraints** | What must NOT change / limits? | — → "keep the JSON shape backward-compatible; no new deps" |
| **References** | What pattern to follow? | — → "mirror `@src/api/users.ts`" |
| **Acceptance / check** | How do we know it's done? | "make it work" → "`npm test src/api/orders.test.ts` passes; show output" |
| **Approach / mode** | How should Claude work? | — → "plan first" / "use TDD" / "just do it" |
| **Output** | What should Claude return? | — → "show the diff and the test results" |

The **acceptance check** is the highest-value ingredient — it's the difference between a session
the user babysits and one Claude closes on its own. Always try to supply a real one.

## Scorecard (show this — it teaches the pattern)

```text
Goal        ✓     Context     ✗ → added    Constraints ✗ → added
References  ✗→added   Check   ✗ → added    Approach    ~ → set    Output ✓
Before: 2/7   After: 7/7
```

## Output template

```text
<one or two sentences: the concrete goal, naming the real target file(s) with @>

Context: <why this matters / where it lives>
Constraints: <what must not change; limits; no new deps>
Follow: <real existing file/pattern to mirror, with @path>
Done when: <a real check — e.g. `npm test path/to.test.ts` — and "show the output">
Approach: <plan first | TDD | just do it>
```

Drop any line that genuinely doesn't apply. Prefer natural prose for tiny tasks; use the labeled
lines when there are real constraints.

## Example (grounded — note: no brackets)

**Raw:** `make the checkout page faster`

**Grounding moves:**
- `Glob **/checkout*` → `src/checkout/CheckoutPage.tsx`
- `package.json` scripts → `"test": "vitest run"`, `"build": "vite build"`
- `Grep "useMemo\|React.memo" src` → `src/cart/CartPage.tsx` already memoizes its list

**Scorecard:** Before 1/7 → After 7/7

**Optimized:**

```text
Speed up the checkout page in @src/checkout/CheckoutPage.tsx — its product list re-renders on
every keystroke in the promo-code field.

Context: the list isn't memoized, so typing recomputes and re-renders all rows.
Constraints: don't change checkout behavior or the order-submit payload; no new dependencies.
Follow: the memoization pattern already in @src/cart/CartPage.tsx (React.memo on rows + useMemo
on the derived list).
Done when: `npx vitest run src/checkout` passes, `npm run build` succeeds, and typing in the
promo field no longer re-renders product rows (verify with a render count or React DevTools).
Show me the diff and the test output.
Approach: plan first, then implement.
```

## Mode specifics

- **Diagnose** a failed prompt: name the failure → the missing ingredient it maps to → the fix.
  "Claude refactored the whole file" = missing **Constraints** (add "only change X; no refactors").
  "Claude solved the wrong thing" = missing **Goal/Context** (name the file + symptom). Also tell
  the user the session fix: after two bad corrections, `/clear` and resend the optimized prompt;
  use `/rewind` to undo Claude's changes.
- **Generate** from a bare goal: ground first, then if scope is still ambiguous ask the 3
  questions before writing — don't generate a confident prompt on top of unknowns.
- **Spec** a big feature: see the interview→SPEC.md→fresh-session pattern in the reference.

## Common mistakes

| Mistake | Fix |
|---|---|
| Emitting `[bracketed placeholders]` | Ground in the repo; resolve to real paths/commands, or ask one question |
| Stacking unrelated tasks in one prompt | One task per prompt; `/clear` between them |
| "Make it better" with no check | Name a real verification: a test command, a build, a screenshot to compare |
| Describing the fix instead of the symptom | Give symptom + likely location; let Claude find the cause |
| Over-specifying the obvious | Cut filler; keep only constraints Claude can't infer |
| Dribbling context over many turns | Front-load intent + constraints in the first message — Opus 4.8 rewards this |

## Deeper guidance

For the full strategy tables, model-specific behavior (literalism, autonomy, over-eagerness),
the verification-gating ladder, rich-context input (`@files`, images, URLs, piping), plan-mode
decisions, mid-task course-correction phrasing, the interview→spec pattern, and reusable prompt
snippets, read [references/claude-code-prompting-guide.md](references/claude-code-prompting-guide.md).

Source material: Anthropic's publicly documented Claude Code prompting guidance
(https://code.claude.com/docs), summarized in this skill's own words.

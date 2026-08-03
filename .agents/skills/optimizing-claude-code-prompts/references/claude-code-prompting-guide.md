# Claude Code Prompting Guide (deep reference)

Distilled from `claude-code-best-practices.md` and `prompting-best-practices.md` (repo root).
Load this when the basic seven-ingredient pass in SKILL.md isn't enough — large features,
model-behavior tuning, or diagnosing why Claude Code keeps going off track.

## Contents
- [1. The seven ingredients, expanded](#1-the-seven-ingredients-expanded)
- [2. Verification: give Claude a check it can run](#2-verification-give-claude-a-check-it-can-run)
- [3. Plan first vs. just do it](#3-plan-first-vs-just-do-it)
- [4. Model behavior to prompt around (Opus 4.8)](#4-model-behavior-to-prompt-around-opus-48)
- [5. Feed rich context](#5-feed-rich-context)
- [6. Big features: interview → spec → fresh session](#6-big-features-interview--spec--fresh-session)
- [7. Session hygiene the optimizer should recommend](#7-session-hygiene-the-optimizer-should-recommend)
- [8. Anti-patterns to rewrite away](#8-anti-patterns-to-rewrite-away)
- [9. Reusable prompt snippets](#9-reusable-prompt-snippets)

## 1. The seven ingredients, expanded

Each "before → after" shows the kind of rewrite the optimizer performs.

| Strategy | Before | After |
|---|---|---|
| **Scope the task** | "add tests for foo.py" | "write a test for foo.py covering the case where the user is logged out. avoid mocks." |
| **Point to sources** | "why does ExecutionFactory have such a weird api?" | "look through ExecutionFactory's git history and summarize how its api came to be" |
| **Reference patterns** | "add a calendar widget" | "look at how widgets are built on the home page — HotDogWidget.php is a good example. follow that pattern to add a calendar widget. build from scratch without new libraries." |
| **Describe the symptom** | "fix the login bug" | "users report login fails after session timeout. check token refresh in src/auth/. write a failing test that reproduces it, then fix it." |

Vague prompts still have a place: when *exploring*, `"what would you improve in this file?"`
surfaces things the user wouldn't have thought to ask. Optimize for precision when the user
wants a specific outcome; leave room when they're fishing.

## 2. Verification: give Claude a check it can run

Without a runnable check, "looks done" is the only stop signal and the user becomes the
verification loop. A check is anything returning pass/fail in the conversation: a test suite,
a build exit code, a linter, a diff against a fixture, or a screenshot compared to a design.

Gating ladder, from lightest to strongest — pick based on how much the user is watching:

1. **In one prompt** — "run the tests after implementing and fix failures." Works today on any task.
2. **Across a session** — set the check as a `/goal` condition; an evaluator re-checks every turn.
3. **Deterministic gate** — a Stop hook runs the check as a script and blocks the turn until it passes.
4. **Second opinion** — a verification subagent / `/code-review` re-checks in fresh context.

Always ask for **evidence, not assertion**: the command run and its output, or a screenshot.

UI work: "[paste screenshot] implement this design. take a screenshot of the result, compare
to the original, list differences, and fix them."

Bugs: "fix it and verify the build succeeds. address the root cause, don't suppress the error."

## 3. Plan first vs. just do it

Recommend **plan mode** when the approach is uncertain, the change spans multiple files, or
the user is unfamiliar with the code. Skip it when the diff fits in one sentence (typo, log
line, rename). The four-phase loop: **Explore → Plan → Implement → Commit**, with exploration
and planning done in plan mode (read-only) before any edits.

## 4. Model behavior to prompt around (Opus 4.8)

- **Literal instruction following.** It won't generalize an instruction from one item to the
  rest. If something should apply broadly, say so: "apply this to every section, not just the first."
- **Autonomy.** It reasons more after user turns and works long-horizon. Specify task, intent,
  and constraints **upfront in the first message** to maximize autonomy and token efficiency.
  Ambiguous prompts dribbled across turns reduce both performance and efficiency.
- **Over-eagerness / over-engineering.** It may add files, abstractions, and flexibility nobody
  asked for. When the user wants minimalism, add: "Only make changes directly requested or
  clearly necessary. Don't add features, abstractions, docstrings, or defensive code beyond
  what's needed for this task."
- **Action vs. suggestion.** "Can you suggest changes…" often yields only suggestions. For
  action, use imperatives: "Change this function to…", "Make these edits to…".
- **Risky actions.** For autonomous runs, add: "Take local, reversible actions freely, but ask
  before anything hard to reverse (force-push, deleting files/branches, dropping tables) or
  visible to others (pushing, commenting on PRs)."
- **Hallucination guard.** "Never make claims about code you haven't opened. Read referenced
  files before answering."

## 5. Feed rich context

- **`@path`** references a file so Claude reads it before responding — better than describing where code lives.
- **Paste images** (screenshots, mockups) directly into the prompt.
- **Give URLs** for docs/APIs; allowlist frequent domains with `/permissions`.
- **Pipe data**: `cat error.log | claude` sends contents straight in.
- **Let Claude fetch**: tell it to pull context itself via Bash, MCP tools, or file reads.

## 6. Big features: interview → spec → fresh session

For larger work, don't write the mega-prompt by hand. Have Claude interview the user first:

```text
I want to build [brief description]. Interview me in detail using the AskUserQuestion tool.
Ask about technical implementation, UI/UX, edge cases, concerns, and tradeoffs. Don't ask
obvious questions — dig into the hard parts I might not have considered. Keep interviewing
until we've covered everything, then write a complete spec to SPEC.md.
```

The best specs are self-contained: they name the files and interfaces involved, state what's
out of scope, and end with an end-to-end verification step. Then start a **fresh session** to
execute the spec with clean context.

## 7. Session hygiene the optimizer should recommend

When a user is frustrated with results, the fix is often the *session*, not the prompt:

- **Course-correct early** with `Esc`; `Esc Esc` or `/rewind` to restore prior state.
- **`/clear` between unrelated tasks** — the "kitchen sink session" pollutes context.
- **After two failed corrections, `/clear` and rewrite** the initial prompt with what was learned.
  A clean session with a better prompt beats a long one full of failed attempts.
- **Subagents for investigation** — "use subagents to investigate X" keeps the main context clean.

### Mid-task course-correction phrasing

When Claude is *actively* going wrong, the user doesn't need a new prompt — they need a sharp
redirect. Hand them phrasing like:

- Scope creep: "Stop. Revert the changes outside `@target.ts` and do only the one change I asked for."
- Wrong root cause: "That treats the symptom. Find why `<symptom>` happens before changing anything; show me the cause first."
- Over-engineering: "Too much. Remove the abstraction/helper you added and inline the simplest version that passes the test."
- Unverified 'done': "Don't tell me it works — run `<check>` and paste the output."
- Going in circles: "`/clear` and start fresh — here's a tighter prompt: <optimized prompt>."

### Grounding checklist (run before writing any optimized prompt)

1. Target file(s) resolved to real paths via `Glob`/`Grep`? 
2. The "Done when" check is a real command (from `package.json`/`Makefile`/`pyproject.toml`/CI)?
3. "Follow the pattern" names a real sibling file that already does it?
4. The symptom's likely location grep'd to a real directory?
5. Zero `[brackets]` left in the output? If not, go look or ask one question.

## 8. Anti-patterns to rewrite away

- **Kitchen-sink prompt** — multiple unrelated tasks at once → split, one per prompt.
- **Trust-then-verify gap** — plausible code, no edge-case check → always attach verification.
- **Infinite exploration** — unscoped "investigate" → scope narrowly or delegate to a subagent.
- **Over-prompting** — "CRITICAL: you MUST…" everywhere → on current models, normal phrasing
  ("Use this when…") avoids over-triggering. Reserve emphasis for the one rule that matters most.
- **"Don't do X" formatting rules** — prefer telling Claude what TO do ("respond in flowing prose")
  over what to avoid ("don't use markdown").

## 9. Reusable prompt snippets

Drop these into an optimized prompt when the matching behavior is needed.

**Coverage over filtering (review/bug-finding):**
```text
Report every issue you find, including low-severity or uncertain ones. Don't filter for
importance yet — coverage is the goal. Include a confidence level and severity for each.
```

**Minimal / no over-engineering:**
```text
Only make changes directly requested or clearly necessary. No new features, abstractions, or
defensive code beyond what this task needs. Don't add comments or types to code you didn't change.
```

**General, non-overfit solution:**
```text
Implement a correct general solution for all valid inputs, not just the test cases. Don't
hard-code to the tests or add workaround scripts. If a test seems wrong, tell me instead of
working around it.
```

**Persist across context compaction (long autonomous runs):**
```text
Your context will be compacted automatically as it fills, so don't stop early for token
reasons. Save progress and state to disk before the window refreshes, and complete the task fully.
```

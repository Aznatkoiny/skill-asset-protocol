# Claude Code Prompting Guide (deep reference)

Summarizes publicly documented Claude Code prompting guidance (see https://code.claude.com/docs)
in this project's own words.
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
| **Scope the task** | "add tests for the csv parser" | "write one unit test for csv-parser.ts covering a row that contains a quoted comma. exercise the real parser — no stubs." |
| **Point to sources** | "why is SyncScheduler's retry logic so convoluted?" | "walk SyncScheduler through the commit log and summarize which changes shaped its retry logic" |
| **Reference patterns** | "add a CSV export button" | "see how export buttons are wired on the reports screen — PdfExportButton.tsx is the model to copy. follow that pattern to add a CSV export button. no new dependencies." |
| **Describe the symptom** | "fix the search bug" | "search keeps returning stale results after a record is renamed. suspect the cache invalidation in src/search/. write a failing test that reproduces it, then fix it." |

Vague prompts still have a place: when *exploring*, `"what's the weakest part of this module?"`
surfaces things the user wouldn't have thought to ask. Optimize for precision when the user
wants a specific outcome; leave room when they're fishing.

## 2. Verification: give Claude a check it can run

Without a runnable check, "looks done" is the only stop signal and the user becomes the
verification loop. A check is anything returning pass/fail in the conversation: a test suite,
a build exit code, a linter, a diff against a fixture, or a screenshot compared to a design.

Gating ladder, from lightest to strongest — pick based on how much the user is watching:

1. **In one prompt** — "when the implementation is in, run the suite and fix whatever fails." Works today on any task.
2. **Across a session** — set the check as a `/goal` condition; an evaluator re-checks every turn.
3. **Deterministic gate** — a Stop hook runs the check as a script and blocks the turn until it passes.
4. **Second opinion** — a verification subagent / `/code-review` re-checks in fresh context.

Always ask for **evidence, not assertion**: the command run and its output, or a screenshot.

UI work: "[attach mockup] build this screen, then screenshot what you built, put it next to
the mockup, note every mismatch, and iterate until they agree."

Bugs: "fix it, then prove it: run the build and the affected tests. treat the underlying
cause — don't just silence the error."

## 3. Plan first vs. just do it

Recommend **plan mode** when the approach is uncertain, the change spans multiple files, or
the user is unfamiliar with the code. Skip it when the diff fits in one sentence (typo, log
line, rename). The four-phase loop: **Explore → Plan → Implement → Commit**, with exploration
and planning done in plan mode (read-only) before any edits.

## 4. Model behavior to prompt around (Opus 4.8)

- **Literal instruction following.** It won't generalize an instruction from one item to the
  rest. If something should apply broadly, say so: "do this for every entry in the list, not
  only the one I pointed at."
- **Autonomy.** It reasons more after user turns and works long-horizon. Specify task, intent,
  and constraints **upfront in the first message** to maximize autonomy and token efficiency.
  Ambiguous prompts dribbled across turns reduce both performance and efficiency.
- **Over-eagerness / over-engineering.** It may add files, abstractions, and flexibility nobody
  asked for. When the user wants minimalism, add: "Keep the change minimal: touch only what
  this task requires. No extra helpers, no speculative flexibility, no doc comments on code
  you didn't change."
- **Action vs. suggestion.** "Can you suggest changes…" often yields only suggestions. For
  action, use imperatives: "Rename this method to…", "Apply these edits to…".
- **Risky actions.** For autonomous runs, add: "Proceed freely on anything you can undo
  locally, but check with me before destructive operations (history rewrites, deleting
  branches or data) and before anything other people will see (pushes, PR comments)."
- **Hallucination guard.** "Only describe code you have actually read in this session — open
  a file before making statements about it."

## 5. Feed rich context

- **`@path`** references a file so Claude reads it before responding — better than describing where code lives.
- **Paste images** (screenshots, mockups) directly into the prompt.
- **Give URLs** for docs/APIs; allowlist frequent domains with `/permissions`.
- **Pipe data**: `cat error.log | claude` sends contents straight in.
- **Let Claude fetch**: tell it to pull context itself via Bash, MCP tools, or file reads.

## 6. Big features: interview → spec → fresh session

For larger work, don't write the mega-prompt by hand. Have Claude interview the user first:

```text
I want to build [one-line description]. Use the AskUserQuestion tool to interview me about it:
implementation approach, UX, edge cases, risks, and tradeoffs. Skip questions with obvious
answers — push on the decisions I haven't thought through yet. When nothing important is left
unresolved, write the full spec to SPEC.md.
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
- **"Don't do X" formatting rules** — prefer telling Claude what TO do ("answer in plain
  paragraphs") over what to avoid ("no bullet lists").

## 9. Reusable prompt snippets

Drop these into an optimized prompt when the matching behavior is needed.

**Coverage over filtering (review/bug-finding):**
```text
List every finding, including minor or doubtful ones. Breadth matters more than ranking at
this stage. Tag each finding with how severe it looks and how confident you are in it.
```

**Minimal / no over-engineering:**
```text
Make only the edits this task actually requires — no added abstractions, features, or guard
rails beyond the ask. Leave untouched code exactly as it was: no drive-by comments, renames,
or type annotations.
```

**General, non-overfit solution:**
```text
Solve the problem for the full input space, not merely the visible test cases. No hard-coded
expected values, no special-casing the suite. If you believe a test itself is wrong, flag it
to me rather than coding around it.
```

**Persist across context compaction (long autonomous runs):**
```text
On long runs your context gets compacted automatically — never wind down early to conserve
tokens. Checkpoint progress and state to files as you go so work survives the refresh, and
keep going until the task is genuinely finished.
```

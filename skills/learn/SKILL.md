---
name: learn
description: Review the LEARN candidates that /casa:investigate wrote under learn/pending/ and promote the ones the analyst approves into the standards skill's lessons file. Nothing is promoted without an explicit approval. Supports headless --list, --approve and --discard.
argument-hint: "[--list | --approve <file> | --discard <file>]"
---

# /casa:learn

The LEARN phase of an investigation writes a candidate note under `learn/pending/`. This skill
is the only path from a candidate to `${CLAUDE_PLUGIN_ROOT}/skills/standards/references/lessons.md`, and the analyst
decides every promotion. You never edit workflow cards, agents or the standards skill here.

## Modes

- **`/casa:learn`** (interactive): list every `learn/pending/*.md` with a one-line summary, then
  for each note ask the analyst, with the AskUserQuestion tool, whether to keep it (promote),
  discard it, or leave it pending. Act on each answer as below.
- **`/casa:learn --list`**: print the summaries and stop. Change nothing.
- **`/casa:learn --approve <file>`**: promote that one note without asking (the command line
  is the approval). Headless use.
- **`/casa:learn --discard <file>`**: archive that one note as discarded without asking.

Find notes with the Glob tool. Read them with the Read tool. Do not run shell commands.

## Promote

1. From the note, distil one entry: the rule, threshold or correction that proved out, stated
   in one or two sentences a future run can apply, plus the evidence reference it rests on
   (a fixture name and rule IDs, a grade file, or a quoted specialist disagreement).
2. Append to `${CLAUDE_PLUGIN_ROOT}/skills/standards/references/lessons.md` under a heading of the form
   `## <YYYY-MM-DD> <source slug>` with the entry, the evidence reference and the note's file
   name. Do not rewrite earlier entries. If the file still contains the `_(empty)_`
   placeholder, remove that line.
3. Archive the note: write a copy to `learn/archive/<same file name>` with the Write tool,
   then remove the pending file with `rm learn/pending/<file>` (the permission rules ask
   before `rm`; in a headless run that prompt is refused, so say the pending copy remains).
   Report what was appended.

## Discard

Write the note to `learn/archive/discarded-<file name>` and tell the analyst the pending copy
can be deleted. Nothing is appended to the lessons file.

## Rules

- A lesson must be actionable by a future investigation or evaluation. "The run was slow" is
  not a lesson; "split conjunction hypotheses so each component gets its own verdict" is.
- Never promote a note that cites telemetry outside the fixtures or the intake it came from,
  and never copy hostnames, users or addresses into a lesson; refer to the fixture instead.
- The lessons file is read by the standards skill's citation rules and by analysts. Keep each
  entry under ten lines.

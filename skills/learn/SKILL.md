---
name: learn
description: Review the LEARN candidates that /casa:investigate wrote under learn/pending/ and promote the ones the analyst approves into the analyst's lessons file in the plugin data directory, which every investigation reads. Nothing is promoted without an explicit approval. Supports headless --list, --approve and --discard.
argument-hint: "[--list | --approve <file> | --discard <file>]"
---

# /casa:learn

The LEARN phase of an investigation writes a candidate note under `learn/pending/`. This skill
is the only path from a candidate to a lesson, and the analyst decides every promotion.
Approved lessons go to `${CLAUDE_PLUGIN_DATA}/lessons.md`, which survives plugin updates.
`${CLAUDE_PLUGIN_ROOT}/skills/standards/references/lessons.md` is the read-only seed that ships with the plugin; never
write to it. You never edit workflow cards, agents or the standards skill here.

## Modes

- **`/casa:learn`** (interactive): list every pending note with a one-line summary, then for
  each note ask the analyst, with the AskUserQuestion tool, whether to keep it (promote),
  discard it, or leave it pending. Act on each answer as below.
- **`/casa:learn --list`**: print the summaries and stop. Change nothing.
- **`/casa:learn --approve <file>`**: promote that one note without asking (the command line
  is the approval). Headless use.
- **`/casa:learn --discard <file>`**: archive that one note as discarded without asking.

Find notes with the Glob tool and read them with the Read tool. Do not run shell commands.
A note under `learn/pending/` whose file name already exists under `learn/archive/` (as is, or
with a `discarded-` prefix) is settled: leave it out of the list and of every prompt, and say
it can be deleted.

## Promote

1. From the note, distil one entry: the rule, threshold or correction that proved out, stated
   in one or two sentences a future run can apply, and one line on what the run showed.
2. Append the entry to `${CLAUDE_PLUGIN_DATA}/lessons.md` under a heading of the form
   `## <YYYY-MM-DD> <short generic topic>`. Read the file first and write it back with the
   entry added at the end; if it does not exist yet, create it with a `# Lessons` title. Never
   rewrite or drop an earlier entry.
3. Archive the note: write a copy to `learn/archive/<same file name>` with the Write tool, with
   one added last line naming the lesson heading it became. The archive keeps the provenance
   (intake, run id, rule IDs) that the lesson itself leaves out. Report what was appended.

## Discard

Write the note to `learn/archive/discarded-<file name>` and tell the analyst the pending copy
can be deleted. Nothing is appended to the lessons file.

## Rules

- A lesson must be actionable by a future investigation or evaluation. "The run was slow" is
  not a lesson; "split conjunction hypotheses so each component gets its own verdict" is.
- Every investigation reads the lessons file, so a lesson is method, never case data. It names
  no intake, fixture, run id, host, account, address or rule ID, and it quotes no alert text;
  the archived note carries those. A note whose only content is a case-specific answer ("this
  intake is High") is not a lesson; discard it or leave it pending.
- Keep each entry under ten lines.

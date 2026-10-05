---
name: evaluate
description: Grade a CASA brief against a fixture's ground truth. Runs the deterministic grader (lint, status, thread count, confidence, citations, option kinds), then the evaluator agent for the rubric items, and merges both into one casa.grade/v1 record under evals/results/.
argument-hint: <fixture> [--brief <path>]
---

# /casa:evaluate

Grades one brief against one fixture. The deterministic half is the gate; the rubric half is
advisory and comes from `casa:evaluator`. Nothing here edits a brief.

## Steps

1. **Resolve inputs.** `<fixture>` is a name under `intake/fixtures/` (for example
   `brute-force-dc-chain`). Intake: `intake/fixtures/<fixture>.intake.json`. Expected:
   `intake/fixtures/<fixture>.expected.json`. Brief: the `--brief` path if given; otherwise the
   newest `briefs/*<fixture>*.brief.md`; otherwise `evals/samples/<fixture>.run1.brief.md`.
   If any of the three is missing, say so and stop.
2. **Machine grade.** Run, as a single Bash command:

   ```
   bun evals/Grade.ts --brief <brief> --expected <expected> --intake <intake> --json
   ```

   Keep the printed `path` (the grade file). A non-zero exit means a machine check failed;
   continue to the rubric anyway so the record is complete, but say which checks failed.
3. **Rubric grade.** Use the Agent tool once with `subagent_type` `casa:evaluator` and a prompt
   that gives the four paths (brief, expected, intake, grade file) and asks for the rubric file
   under `evals/results/<fixture>/`. Take the rubric file path from its reply.
4. **Merge.** Run:

   ```
   bun evals/Grade.ts --brief <brief> --expected <expected> --intake <intake> --rubric <rubric file>
   ```

5. **Report.** Print the machine table, the rubric lines with their quotations, the score
   line, and the path of the merged grade file. Do not restate the brief.

## Rules

- The machine checks are deterministic and final. If you disagree with one, the fix is in the
  brief or in `expected.json`, never in the grade file.
- The evaluator's quotations must be verbatim. If a quotation does not appear in the brief,
  treat that rubric item as failed and say so.
- Results are gitignored. If a grade should be kept, copy the brief under `evals/samples/` as
  `<fixture>.runN.brief.md`; the test suite lints every run sample.

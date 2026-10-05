# evals/plugin-eval

Reserved for `claude plugin eval` cases (`case.yaml` or `prompt.md` plus `graders/`). The
manifest points the command here so it never scans the CASA grader's own files under `evals/`.
CASA's evaluation runs through `bun evals/Grade.ts` and `/casa:evaluate` instead; the plugin
eval harness is experimental and not adopted. This directory is intentionally empty.

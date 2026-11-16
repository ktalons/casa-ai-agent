# Lessons

The seed lessons that ship with this release of CASA. This file is read-only: `/casa:learn`
never writes here. Lessons an analyst approves go to `lessons.md` in the plugin's data
directory, which survives plugin updates, and `/casa:investigate` reads both files on every
run. Each entry gives a date, a short generic topic, the rule that proved out, and what the
run showed. No entry names an intake, a fixture, a host, an account, an address or a rule ID.

## 2026-10-05 confidence scope on multi-host chains

When a workflow card's High criterion is met by only one segment of a multi-host thread, state
the confidence per scope (the segment that meets the criterion, and the whole chain) instead
of one thread-level rating. Rate the whole chain with the standards confidence rubric over all
of its independent references; do not leave it lower than those references support.
Evidence: a run in which three specialists split between High, Medium and undetermined on one
multi-host chain while agreeing that its final segment met the card's High criterion.

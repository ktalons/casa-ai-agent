# Lessons

Validated patterns promoted from `learn/pending/` by `/casa:learn` after analyst sign-off.
Each entry: date, fixture or case slug, the rule or threshold that proved out, and the evidence
reference that justified it. Nothing is written here automatically.

## 2026-10-05 brute-force-dc-chain

When a workflow card's High criterion is met by only one segment of a multi-host thread, state
the confidence per scope (the segment that meets the criterion, and the whole chain) instead of
one thread-level rating. Specialists otherwise split between High and Medium on the same
evidence because the ladder does not say which scope it applies to.
Evidence: fixture brute-force-dc-chain; log-analyst rated the full chain High, network-analyst
Medium, endpoint-analyst undetermined at Medium, all agreeing the DC segment meets the criterion.
Note: 2026-10-05-brute-force-dc-chain.md
Amendment (same day): the DCSync and auth cards now carry the cross-host rule that decides the
whole-chain level (a rule description asserting the source relation plus the time order, with a
recon-delta change on the first host as the second independent source, is High for the chain).
State both scopes, but do not leave the chain at Medium when that rule is met.

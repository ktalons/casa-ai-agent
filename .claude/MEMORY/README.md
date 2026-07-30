# MEMORY

Local capture from CASA sessions. Everything under this directory except these README scaffolds is **gitignored** — session content, work state, and captures stay on the analyst's machine and are never committed.

## Layout

| Directory | Holds | Written by |
|---|---|---|
| `WORK/` | Per-session work state | ResponseCapture (Stop) |
| `STATE/` | Fast runtime pointers (e.g. current work) | ResponseCapture (Stop) |
| `LEARNING/` | Session summaries / derived notes | SessionSummary (SessionEnd) |
| `RESEARCH/` | Subagent output captures | AgentOutputCapture (SubagentStop) |

Claude Code's own `projects/` transcripts remain the source of truth for full session history; these directories hold only the domain-specific slices the hooks pull out. See [`../hooks/README.md`](../hooks/README.md) for the hooks that write here.

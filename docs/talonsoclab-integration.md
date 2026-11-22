# Running CASA on TalonSocLab

The runbook for the day the lab is ready: install the plugin into the lab checkout, produce an
intake v3 artifact with the CASA producer, run the first investigation, then the daily loop.
Steps 2 and 4 were exercised against a scratch copy of the lab on 2026-10-05; the producer
steps that need a live indexer wait for a lab ISC. The exact commands are below so the steps
can be repeated verbatim.

Two repos, two planes. TalonSocLab is the data plane: it collects, filters and cites
telemetry, and the CASA producer turns its Wazuh alerts into `<output-root>/intake/<date>-intake.json`.
CASA is the reasoning plane: a Claude Code plugin installed **into the lab checkout**, whose
`output_root` option (step 3) puts briefs, proposed detections and learn candidates outside
the tracked tree. CASA never writes into its own repo from a lab run; lessons you approve go
to the plugin's data directory (see step 2).

## 1. Prerequisites

| Need | Why |
|---|---|
| Claude Code 2.1.289 or later | plugin skills reference their own files through `${CLAUDE_PLUGIN_ROOT}`, substituted at load |
| bun | runs the producer, validator, lint and grader that ship with the plugin |
| jq | the install script merges permission rules with it |

Check: `claude --version`, `bun --version`, `jq --version`.

## 2. Install CASA into the lab checkout

From the lab checkout root (`talonsoclab/`), on the machine where you also maintain CASA:

```bash
bash /path/to/casa-ai-agent/scripts/install-into-project.sh --source /path/to/casa-ai-agent
```

On any other machine, install from GitHub instead:

```bash
curl -fsSL https://raw.githubusercontent.com/ktalons/casa-ai-agent/v5.1.0/scripts/install-into-project.sh | bash
```

The script is idempotent. It:

1. adds the CASA marketplace and installs `casa@casa` at **project** scope, which records both in
   the lab's `.claude/settings.json` so every clone of the lab gets the same plugin (pass
   `--scope local` to keep it in the gitignored `settings.local.json` instead);
2. merges CASA's recommended permission block into `.claude/settings.json` (array union, the
   previous file kept as `settings.json.bak`): the read-only analysis commands are allowed,
   destructive and network commands are denied, secrets stay unreadable,
   and reads under the plugin root are allowed (the skills' templates and reference tables
   live there, outside the project, so without that rule a headless run stops at the first
   template read). The specialists have no shell, so these Bash rules are for the main
   thread: the validator, the lint, the grader, and any raw-data queries (`jq`, `tshark -r`,
   `zeek-cut`) you approve when you hand CASA raw telemetry;
3. creates `briefs/`, `detections/proposed/`, `detections/accepted/`, `learn/pending/`,
   `learn/archive/`, `evals/results/`, `engagements/`;
4. appends a marked block to `.gitignore` so run output is never committed (only
   `detections/accepted/` is tracked);
5. prints `claude plugin list` filtered to casa and the smoke-test command.

**Where approved lessons live.** `/casa:learn` appends each lesson you approve to
`lessons.md` in the plugin's data directory, `${CLAUDE_PLUGIN_DATA}`, which Claude Code keeps
under `~/.claude/plugins/data/` and leaves alone when the plugin updates. The plugin's own
`skills/standards/references/lessons.md` is a read-only seed that ships with each release.
Every investigation reads both, so a lesson is in force from the next run whichever way you
installed. To share a lesson with other installs, copy it into the seed in your CASA checkout
and commit it there. `--source` still matters for one thing: it reads the plugin in place, so
an edit to a card or agent in your checkout takes effect without a reinstall.

Commit the lab's `.claude/settings.json` and `.gitignore` changes.

## 3. Produce the intake with the CASA producer

CASA ships its own producer, `intake/producers/wazuh.ts` (Bun, no dependencies). It reads
Wazuh alerts, from a recorded export or from a live indexer, and writes one
`talonsoclab.soc-intake/v3` intake. It replaces the lab's former Python digest producer, which
the lab removed from its public tree on 2026-11-04; the lab's history was rewritten that day,
so commit IDs recorded before it no longer resolve there.

What v3 carries beyond v2 (field table: [`intake/README.md`](../intake/README.md)): the engine
that raised each alert with its own IDs (a Suricata signature ID next to the Wazuh rule ID),
ports and protocol, the acting `subject_user` apart from the `target_user` with its logon
type, typed Sysmon fields for events 1, 3, 11, 13 and 22, Suricata EVE fields, timestamps with
microseconds and UTC offsets, a level floor plus a rule-ID include list, and per-day counts so
a truncated window shows which days lost alerts.

**Dry run (works today, no lab needed).** Replay a recorded export and validate the result:

```bash
bun /path/to/casa-ai-agent/intake/producers/wazuh.ts --replay /path/to/casa-ai-agent/intake/raw/brute-force-dc-chain.v2.alerts.jsonl --out /tmp/casa-dry/intake.json
bun /path/to/casa-ai-agent/intake/Validate.ts /tmp/casa-dry/intake.json
```

In replay mode the window ends at the newest alert in the recording (or at `--window-end`),
not at now, so old data validates. `--min-level`, `--include-rules`, `--cap` and `--lookback`
apply exactly as they do live.

**Live run (after a lab ISC exists).** Nothing in this leg touches the lab; these are the steps
for the day the lab wires CASA in. The producer talks HTTPS only, verifies the indexer's
certificate against the CA you give it, refuses a plain `http://` URL or one with a user name
in it, and takes the password from the environment or a file, never from its command line. It
never prints the password or the authorization header.

```bash
export WAZUH_INDEXER_URL=https://<indexer-host>:9200
export WAZUH_INDEXER_USER=<read-only-user>
bun /path/to/casa-ai-agent/intake/producers/wazuh.ts --password-file <path-to-password-file> --ca-file <path-to-root-ca.pem> --include-rules <pack-rule-ids> --redact --out "<output-root>/intake/$(date -u +%F)-intake.json"
bun /path/to/casa-ai-agent/intake/Validate.ts "<output-root>/intake/$(date -u +%F)-intake.json"
```

The validator prints the intake's SHA-256 under its tick line. A brief records that value as
`intake.sha256`, and the lint reports a brief whose recorded hash is not the file's, so a brief
always names the exact intake it was written from.

`--redact` applies the lab's own mapping before anything is written: private IPv4 addresses
become `192.0.2.n` and private IPv6 addresses `2001:db8::n` in order of first sight, account
SIDs become `S-1-5-21-0-0-n`, the machine-derived first field of each Sysmon GUID becomes
zeros, and each `--alias <host>=<alias>` is applied as a whole word. If anything private
survives, the producer writes nothing and names the field.

`--redact` is a second layer, not a guarantee; the first is an output root outside any public
tree. It rewrites addresses written plainly, as reverse-lookup names and as IPv4-mapped forms,
and refuses a base64 run of 16 or more characters that decodes to a private value. It does not
decode percent-encoding, base64 shorter than 16 characters, nested or whitespace-wrapped
encodings, or UTF-16BE, and it does not follow a Sysmon GUID into encoded text. Read an intake
before it goes anywhere public. Pick an `<output-root>` outside any
tracked public path, and set CASA's `output_root` plugin option to the same directory (below),
so briefs and drafts land there too.

A failure names the rule that tripped. Warnings (a technique ID not in the ATT&CK table, a
window whose span disagrees with `lookback_hours`) do not fail.

**Output root.** CASA's `output_root` option (a directory) decides where every run writes:
`briefs/`, `detections/proposed/`, `learn/pending/`, `learn/archive/` and `evals/results/` all
resolve under it, and the plugin's write guard enforces the same root. Left empty, it is the
project directory, as before. Claude Code asks for plugin options when the plugin is enabled.
For a public lab checkout, set it to a directory outside the repository.

## 4. First investigation

From the lab checkout root, where the plugin is installed:

```bash
claude -p "/casa:investigate <output-root>/intake/$(date -u +%F)-intake.json" --permission-mode acceptEdits
bun /path/to/casa-ai-agent/evals/Lint.ts --brief <output-root>/briefs/$(date -u +%F).brief.md --intake <output-root>/intake/$(date -u +%F)-intake.json
```

The brief is `briefs/<date>.brief.md` (the producer's `<date>-intake.json` name is used as is,
without doubling the date). The lint must come back clean: every rule ID, host, technique,
CSF ID and address in the brief traces to the intake or a reference table. There is no ground
truth for a live intake, so `/casa:evaluate` does not apply; read the brief against your own
reading of the alerts. Interactive use is the same without `-p`: start `claude` in the lab
root and type the slash command.

What CASA writes, all under the output root except the last (with the option empty, that is
the lab checkout, where the install script gitignores these paths):

| Path | Written by | Contents |
|---|---|---|
| `briefs/<date>.brief.md` | the Overseer (main thread) | one `casa.brief/v1` block plus the readable brief |
| `detections/proposed/<run_id>-<thread>.*` | `casa:detection-engineer` | Sigma and Wazuh drafts for a supported finding at Medium or above; `<run_id>` is the brief name plus `-r<N>`, new for every run, so a second run never overwrites the first run's drafts |
| `learn/pending/<run_id>.md` | the Overseer | one LEARN candidate per run with findings |
| `evals/results/` | `casa:evaluator`, fixtures only | grades and rubric files |
| `detections/accepted/` | you, by hand | the rules you tested and kept (tracked) |

## 5. The daily loop

After a lab ISC exists, add the producer to cron after the recon run (`%` is escaped because
cron treats it as a line break):

```text
0 7 * * *  WAZUH_INDEXER_URL=https://<indexer-host>:9200 WAZUH_INDEXER_USER=<read-only-user> bun /path/to/casa-ai-agent/intake/producers/wazuh.ts --password-file <path-to-password-file> --ca-file <path-to-root-ca.pem> --redact --out "<output-root>/intake/$(date -u +\%F)-intake.json" >> <log-file> 2>&1
```

Then, each day you review:

1. `claude -p "/casa:investigate <output-root>/intake/<date>-intake.json" --permission-mode acceptEdits`
2. Read the brief. Options are suggestions with trade-offs; nothing is acted on by CASA.
3. If rules were proposed, test them on the manager (`/var/ossec/bin/wazuh-logtest` with a real
   event), then move the keepers to `detections/accepted/` and commit.
4. `/casa:learn` when `learn/pending/` has something worth keeping. Approve or discard each
   note; approved ones append to the lessons file in the plugin's data directory, and the next
   investigation reads them.

A quiet day is a real result: the brief says no findings, states what the `pipeline` block
showed, and recommends a liveness check only when the collector or agent counts look wrong.

## 6. Troubleshooting

- **"sensitive file" or a denied write to `briefs/`.** CASA was loaded with `--plugin-dir`,
  which protects the directory. Install it as the script does (marketplace plus plugin).
- **A `bun ...` command was refused.** The command must match an allow rule exactly, on its
  own, with nothing chained. The recommended block allows `bun */intake/Validate.ts *`,
  `bun */evals/Lint.ts *` and `bun */evals/Grade.ts *`, which match the plugin-root forms the
  skills use. Re-run the install script if the block is missing. Every one of these rules serves
  the main thread; the plugin's guard refuses all shell commands to subagents, so the Grade.ts
  rule in particular is for the main thread only (`/casa:evaluate`).
- **The validator rejects the intake.** It prints the field and the rule. The common ones:
  a timestamp outside the window (producer and indexer clocks disagree), `truncated: true`
  with fewer than `cap` entries, a duplicate `alert_id`.
- **Headless runs prompt or stop.** `claude -p` needs the directory trusted once: start
  `claude` interactively in the lab root and accept the trust dialog.
- **`github-advanced-security` red on CASA pull requests.** GitHub's Copilot scanner hit a
  monthly quota; it is not a CASA failure.

## 7. Updating CASA

With a checkout-path install, `git pull` in the CASA checkout is the update. With a GitHub
install: `claude plugin update casa@casa`. After either, run the lab's smoke test (step 4)
once before relying on it.

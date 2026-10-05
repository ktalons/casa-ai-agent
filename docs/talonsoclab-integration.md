# Running CASA on TalonSocLab

The runbook for the day the lab is ready: install the plugin into the lab checkout, switch the
digest producer to intake v2, run the first investigation, then the daily loop. Everything
here was exercised against a scratch copy of the lab on 2026-10-05; the exact commands are
below so the steps can be repeated verbatim.

Two repos, two planes. TalonSocLab is the data plane: it collects, filters, cites and writes
`digest/<date>-intake.json`. CASA is the reasoning plane: a Claude Code plugin installed
**into the lab checkout**, so briefs, proposed detections and learn candidates land next to
the telemetry they came from. CASA never writes into its own repo from a lab run, with one
deliberate exception, promoted lessons (see step 2).

## 1. Prerequisites

| Need | Why |
|---|---|
| Claude Code 2.1.289 or later | plugin skills reference their own files through `${CLAUDE_PLUGIN_ROOT}`, substituted at load |
| bun | runs the validator, lint and grader that ship with the plugin |
| jq | the install script merges permission rules with it |
| python3 | the lab's digest producer (stdlib only) |

Check: `claude --version`, `bun --version`, `jq --version`, `python3 --version`.

## 2. Install CASA into the lab checkout

From the lab checkout root (`talonsoclab/`), on the machine where you also maintain CASA:

```
bash /path/to/casa-ai-agent/scripts/install-into-project.sh --source /path/to/casa-ai-agent
```

On any other machine, install from GitHub instead:

```
curl -fsSL https://raw.githubusercontent.com/ktalons/casa-ai-agent/v5.0.1/scripts/install-into-project.sh | bash
```

The script is idempotent. It:

1. adds the CASA marketplace and installs `casa@casa` at **project** scope, which records both in
   the lab's `.claude/settings.json` so every clone of the lab gets the same plugin (pass
   `--scope local` to keep it in the gitignored `settings.local.json` instead);
2. merges CASA's recommended permission block into `.claude/settings.json` (array union, the
   previous file kept as `settings.json.bak`): the read-only analysis commands the specialists
   use are allowed, destructive and network commands are denied, secrets stay unreadable,
   and reads under the plugin root are allowed (the skills' templates and reference tables
   live there, outside the project, so without that rule a headless run stops at the first
   template read);
3. creates `briefs/`, `detections/proposed/`, `detections/accepted/`, `learn/pending/`,
   `learn/archive/`, `evals/results/`, `engagements/`;
4. appends a marked block to `.gitignore` so run output is never committed (only
   `detections/accepted/` is tracked);
5. prints `claude plugin list` filtered to casa and the smoke-test command.

**Why the checkout path matters.** `/casa:learn` promotes an approved lesson into the plugin's
own `skills/standards/references/lessons.md`. With `--source /path/to/casa-ai-agent` the plugin is
read in place, so the promoted lesson lands in your CASA checkout and you commit it there.
With a GitHub install it lands in the installed copy under `~/.claude/plugins/`, which the next
update overwrites; copy it back by hand if you run that way.

Commit the lab's `.claude/settings.json` and `.gitignore` changes.

## 3. Switch the digest producer to intake v2

The v2 contract gives CASA what v1 could not carry: the window and filter the producer
applied, whether the cap cut the list, pipeline liveness, per-alert correlation fields
(`alert_id`, `src_ip`, `dst_ip`, `user`, `event_id`, `tactic`, `groups`) and a structured recon
delta. Field table: [`intake/README.md`](../intake/README.md).

The updated producer is in this repo as a drop-in file and as a patch against the lab at
`766dc65`:

```
cd /path/to/talonsoclab
git apply /path/to/casa-ai-agent/docs/talonsoclab/generate_digest-v2.patch
# or: cp /path/to/casa-ai-agent/docs/talonsoclab/generate_digest.py deploy/soc-recon/digest/
```

What changed in `deploy/soc-recon/digest/generate_digest.py`:

- `generated` is an ISO instant; `window` comes from `DIGEST_LOOKBACK` (`24h` or `3d`);
  `filter.cap` from the new `DIGEST_CAP` (default 200); `truncated` is true when the indexer
  reported more matches than the cap.
- `pipeline` comes from one extra size-0 query over the same window with **no** level filter:
  distinct `agent.name` and the newest `@timestamp`. A quiet high-severity window and a dead
  collector now look different to CASA.
- Each detection carries the correlation fields, read from the Wazuh document: `id`,
  `data.srcip` or `data.win.eventdata.ipAddress`, `data.dstip`, `data.srcuser`, `data.dstuser` or
  `data.win.eventdata.targetUserName`, `data.win.system.eventID`, `rule.mitre.tactic`,
  `rule.groups`. Missing values are `null`, lists default to empty.
- `recon_delta` is `{markdown, baseline, changes[]}`. `baseline` is the date of the newest
  `*_baseline.md`; `changes` lists each host under "New subdomains" in the newest delta, one
  entry per port seen for it in `<recon-dir>/latest/httpx.jsonl` (`--recon-dir`, default
  `data/recon`), or `port: 0` when the host was enumerated but never probed live. Nuclei
  findings stay in the markdown.
- `--schema v1` still emits the frozen v1 shape, for rollback. The digest markdown, the
  optional LLM rewrite and the other flags are unchanged.

Dry run before touching cron, with a recorded alert file (two ship with CASA under
`intake/raw/`):

```
cd deploy/soc-recon
python3 digest/generate_digest.py --alerts-file /path/to/casa-ai-agent/intake/raw/brute-force-dc-chain.v2.alerts.jsonl --out-dir /tmp/casa-dry
bun /path/to/casa-ai-agent/intake/Validate.ts /tmp/casa-dry/*-intake.json
```

In replay mode the window is anchored to the recording, not to now, so old data validates.
Then a live run with the lab up, and validate that too:

```
set -a && . ./.env && set +a
python3 digest/generate_digest.py
bun /path/to/casa-ai-agent/intake/Validate.ts digest/$(date -u +%F)-intake.json
```

A failure names the rule that tripped. Warnings (a technique ID not in the ATT&CK table, a
window whose span disagrees with `lookback_hours`) do not fail.

## 4. First investigation

From the lab checkout root, where the plugin is installed:

```
claude -p "/casa:investigate deploy/soc-recon/digest/$(date -u +%F)-intake.json" --permission-mode acceptEdits
bun /path/to/casa-ai-agent/evals/Lint.ts --brief briefs/$(date -u +%F).brief.md --intake deploy/soc-recon/digest/$(date -u +%F)-intake.json
```

The brief is `briefs/<date>.brief.md` (the producer's `<date>-intake.json` name is used as is,
without doubling the date). The lint must come back clean: every rule ID, host, technique,
CSF ID and address in the brief traces to the intake or a reference table. There is no ground
truth for a live intake, so `/casa:evaluate` does not apply; read the brief against your own
reading of the alerts. Interactive use is the same without `-p`: start `claude` in the lab
root and type the slash command.

What CASA writes, all under the lab checkout and all gitignored except the last:

| Path | Written by | Contents |
|---|---|---|
| `briefs/<date>.brief.md` | the Overseer (main thread) | one `casa.brief/v1` block plus the readable brief |
| `detections/proposed/<date>-<thread>.*` | `casa:detection-engineer` | Sigma and Wazuh drafts for a supported finding at Medium or above |
| `learn/pending/<date>-<slug>.md` | the Overseer | one LEARN candidate per run with findings |
| `evals/results/` | `casa:evaluator`, fixtures only | grades and rubric files |
| `detections/accepted/` | you, by hand | the rules you tested and kept (tracked) |

## 5. The daily loop

Add the digest to cron after the recon run, as `crontab.example` already plans:

```
0 7 * * *  cd /opt/soc-recon && set -a && . ./.env && set +a && python3 digest/generate_digest.py >> /var/log/soc-recon.log 2>&1
```

Then, each day you review:

1. `claude -p "/casa:investigate deploy/soc-recon/digest/<date>-intake.json" --permission-mode acceptEdits`
2. Read the brief. Options are suggestions with trade-offs; nothing is acted on by CASA.
3. If rules were proposed, test them on the manager (`/var/ossec/bin/wazuh-logtest` with a real
   event), then move the keepers to `detections/accepted/` and commit.
4. `/casa:learn` when `learn/pending/` has something worth keeping. Approve or discard each
   note; approved ones append to the lessons file in the CASA checkout, which you commit there.

A quiet day is a real result: the brief says no findings, states what the `pipeline` block
showed, and recommends a liveness check only when the collector or agent counts look wrong.

## 6. Troubleshooting

- **"sensitive file" or a denied write to `briefs/`.** CASA was loaded with `--plugin-dir`,
  which protects the directory. Install it as the script does (marketplace plus plugin).
- **A `bun ...` command was refused.** The command must match an allow rule exactly, on its
  own, with nothing chained. The recommended block allows `bun */intake/Validate.ts *`,
  `bun */evals/Lint.ts *` and `bun */evals/Grade.ts *`, which match the plugin-root forms the
  skills use. Re-run the install script if the block is missing.
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

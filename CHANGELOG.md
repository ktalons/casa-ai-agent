# Changelog

All notable changes to CASA. The format follows Keep a Changelog; versions follow semver.
Tags on GitHub: `v5.0.1`, `v5.0.0`, `v4.0.0-pai-legacy`.

## Unreleased

### Added

- Intake v3 (`intake/schema/soc-intake.v3.schema.json`): the engine that raised each alert and
  its own IDs, ports and protocol, `subject_user` and `target_user` with the logon type, typed
  Sysmon fields for events 1, 3, 11, 13 and 22, Suricata EVE fields, timestamps with
  microseconds and UTC offsets, a level floor plus a rule-ID include list, and per-day counts.
  v1 and v2 stay frozen. Each fixture has a v3 twin, and each new rule an invalid fixture.
- `intake/producers/wazuh.ts`, a TypeScript Wazuh producer with no dependencies: replay from a
  recorded export, or live over HTTPS with certificate verification that cannot be turned off;
  the password comes from the environment or a file and is never printed; `--redact` applies
  the lab's address, SID and Sysmon GUID mapping and refuses to write if a private value it
  can read survives; gaps in encoded text are listed in the runbook. Redirects are refused and
  `NODE_TLS_REJECT_UNAUTHORIZED=0` cannot switch verification off.
- An `output_root` plugin option: briefs, drafts, LEARN notes and eval results go under it, and
  the write guard resolves every lane against it, so a lab run can write outside a public tree.

### Removed

- The Python digest producer and its patch under `docs/talonsoclab/`; the runbook now uses the
  TypeScript producer.

### Security

- The write guard recognises CASA subagents by their `agent_id` as well as their name, so a
  bare or changed name can no longer slip past it; any `..` in a write path is refused.
- CASA specialists have no shell. Bash is gone from every agent's tools and the guard denies
  any Bash call from a CASA subagent. Raw-data queries (tshark, zeek-cut, jq over raw alerts)
  become data requests that the main thread runs under the user's own permission settings.
  A read-only command allowlist was tried first and dropped after review found six ways to
  get past its parser.
- If `bun` is missing, the guard blocks CASA subagents instead of failing open, and it runs
  from the plugin's own directory so a project `bunfig.toml` or `.env` cannot change it.

### Changed

- The fabrication lint no longer assumes hosts start with `talon`: known hosts come from the
  intake. Rule IDs must equal a `rule_id` exactly, and users, event IDs, ports, exposures,
  IPv6 addresses, domains, hashes and timestamps are now checked. Real event IDs and ports
  that are absent from the intake are reported, not failed.
- Approved lessons are written to `${CLAUDE_PLUGIN_DATA}/lessons.md`, which survives plugin
  updates, and every investigation reads them.
- `/casa:evaluate` writes the grade and the rubric into the project's `evals/results/`.

### Fixed

- The investigate skill and the workflow cards no longer contain fixture answers or fixture
  rule text, so eval scores measure the method rather than memory.
- `evals/RunFull.ts` runs every intake version's fixtures and strips session and API-key
  variables from the child environment.
- Detection drafts get run-unique names. One rule decides when containment options appear: only for a supported finding at High confidence.

## 5.0.1 (2026-10-05)

The first published release of the v5 line. 5.0.0 tagged the rebuild's merge; 5.0.1 adds
what packaging the TalonSocLab integration turned up.

### Security

- The lint and the grader no longer accept a regular expression for the host naming
  convention. `--host-prefix` takes a plain prefix, validated against the hostname character
  set and escaped before it enters the expression, so a command-line value can no longer
  change the expression's meaning or cost (CodeQL `js/regex-injection`, two alerts).

### Changed

- `--host-pattern <regex>` on `evals/Lint.ts` and `evals/Grade.ts` is now
  `--host-prefix <prefix>`; the default is `talon`.

### Fixed

- Skills and agents reach the plugin's own validator, lint, grader, cards, templates and
  reference tables through the plugin root variable, so CASA works installed into another
  project. Before, those paths were relative to the working directory and only resolved from
  the CASA checkout. A test fails on any bare plugin path.
- The recommended permission block allows the plugin root forms of the validator, lint and
  grader commands and reads under the plugins directory, where the skills' files live after a
  marketplace install.
- Brief names no longer double the date for a producer's `<date>-intake.json`.
- The plugin link script passes the marketplace path in the form the CLI accepts.

### Added

- `scripts/install-into-project.sh`: installs CASA into the project where the telemetry lives,
  merges the permission block, creates the output directories and extends the gitignore.
- `docs/talonsoclab-integration.md`: the runbook for the lab, from install to the daily loop.
- `docs/talonsoclab/`: the lab's digest producer updated to emit intake v2, as a drop-in file
  and as a patch, plus an indexer-shaped replay sample under `intake/raw/`.

## 5.0.0 (2026-10-05)

CASA rebuilt as a Claude Code plugin around the intake contract, the fixtures and the SOC
rules carried over from v4. Everything else is new.

### Added

- Plugin layout: `casa@casa` from this repository's own marketplace; eight specialist agents
  with explicit tool lists (log, network and endpoint analysts, purple team mapper, detection
  engineer, threat intel, evaluator, a scope-gated pentester stub); three skills,
  `/casa:investigate`, `/casa:evaluate`, `/casa:learn`; a standards skill preloaded into every
  agent.
- The investigation loop: OBSERVE, HYPOTHESIZE, INVESTIGATE, VERIFY, MAP, BRIEF, LEARN, run
  from the main thread with specialists in parallel; untrusted telemetry treated as data; a
  quiet branch that spawns nothing and recommends only liveness checks; five workflow cards
  in one form, including DCSync.
- Contracts: JSON Schemas for findings, briefs, ground truth, grades and engagement scopes.
- Verification: a deterministic fabrication lint (every rule ID, host, ATT&CK ID, CSF ID and
  address must trace to the intake or a reference table), a grader with nine machine checks,
  an evaluator agent for the rubric items, reference tables regenerated from MITRE STIX
  (ATT&CK v19.2) and the NIST CPRT export (CSF 2.0), NIST citations verified against the PDFs.
- Intake v2: window, filter, truncation, pipeline liveness, per-detection correlation fields,
  a structured recon delta; a schema-driven validator that refuses keywords it does not
  implement, plus semantic rules; ten invalid fixtures. v1 stays frozen.
- A plugin-level write guard that limits the detection engineer and the evaluator to their
  output directories and fails closed.
- LEARN: candidates under `learn/pending/`, promoted only by `/casa:learn` with analyst
  approval.
- CI: strict plugin validation, typecheck, tests, fixture validation, gitleaks, and a manual
  full eval job.

### Removed

- The inherited PAI-era tree: OSINT, recon, web assessment, prompt injection and voice server
  kit, the hook runtime, the memory scaffold and the installer. Preserved at
  `v4.0.0-pai-legacy`.

## 4.0.0 (2026-07)

The PAI-derived tree with the `soc-intake/v1` contract, three graded fixtures and CI, as it
stood before the rebuild. Tagged `v4.0.0-pai-legacy`.

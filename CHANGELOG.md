# Changelog

All notable changes to CASA. The format follows Keep a Changelog; versions follow semver.
Tags on GitHub: `v5.0.1`, `v5.0.0`, `v4.0.0-pai-legacy`.

## 5.0.1 (2026-10-05)

The first published release of the v5 line. 5.0.0 tagged the rebuild's merge; 5.0.1 adds
what packaging the TalonSocLab integration turned up.

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

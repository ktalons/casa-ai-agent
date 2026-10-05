# detections/

- `proposed/` (gitignored): drafts written by `casa:detection-engineer` for a supported
  finding, as `<date>-<thread>.sigma.yml`, `.wazuh.xml` and `.md` (purpose, logic, test
  criteria, false-positive notes). The write guard allows that agent to write here and nowhere else.
- `accepted/` (tracked): rules a human reviewed and moved here by hand. Nothing lands here automatically.

# NIST citations CASA may use

The standards skill allows a section-level citation only if it appears here. Anything not
listed is cited at document level ("NIST SP 800-92") or not at all.

**Verification status: TRANSCRIBED, NOT YET VERIFIED.** Written without network access to
`csrc.nist.gov`, `nvlpubs.nist.gov` and `airc.nist.gov`. Each line below is from memory of the
published documents and is marked accordingly. Verify against the PDFs, then flip the marks.
Until then, prefer the document-level forms.

| Marker | Meaning |
|---|---|
| `[verified]` | checked against the published PDF by a human |
| `[transcribed]` | believed correct; not yet checked |

## NIST SP 800-92 — Guide to Computer Security Log Management (September 2006)

Document-level citation: `[NIST SP 800-92]`.

| Citation | Title | Status |
|---|---|---|
| §2 | Introduction to Computer Security Log Management | [transcribed] |
| §3 | Log Management Infrastructure | [transcribed] |
| §4 | Log Management Planning | [transcribed] |
| §5 | Log Management Operational Processes | [transcribed] |
| §5.2 | Analyze Log Data | [transcribed] |
| §5.3 | Respond to Identified Events | [transcribed] |

Note: a Revision 1 draft, *Cybersecurity Log Management Planning Guide*, was released for
comment in 2023. Its status and numbering are not recorded here; do not cite it by section.

## NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile (April 2025)

Document-level citation: `[NIST SP 800-61r3]`. Rev. 3 supersedes Rev. 2 (2012); do not cite
Rev. 2 section numbers (for example "§3.2.4") — they do not exist in Rev. 3.

| Citation | Title | Status |
|---|---|---|
| §2 | Incident Response Life Cycle Model | [transcribed] |
| §3 | Cybersecurity Incident Response Recommendations and Considerations (organized by CSF 2.0 Function) | [transcribed] |

Within §3, refer to the CSF 2.0 Function by name ("SP 800-61r3 §3, Detect") rather than a
numbered subsection until those are verified.

## NIST AI RMF 1.0 — Artificial Intelligence Risk Management Framework (January 2023)

Document-level citation: `[NIST AI RMF 1.0]`.

| Citation | Content | Status |
|---|---|---|
| Part 1 §3.4 | Accountable and Transparent (trustworthiness characteristic) | [transcribed] |
| Part 1 §3.5 | Explainable and Interpretable (trustworthiness characteristic) | [transcribed] |
| MEASURE 2.8 | Risks associated with transparency and accountability are examined and documented | [transcribed] |
| MEASURE 2.9 | The AI model is explained, validated, and documented, and AI system output is interpreted within its context | [transcribed] |

Do not cite "MAP 2.3" for explainability; it concerns scientific integrity and TEVV.

## NIST CSF 2.0 (NIST CSWP 29, February 2024)

Cite by subcategory ID from `csf-2.0.json` (for example `[NIST CSF 2.0, DE.AE-03]`). Function
names: GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER. CSF 1.1 IDs such as `PR.AC-*`,
`RS.AN-01`, `DE.CM-04` do not exist in 2.0 and must not appear.

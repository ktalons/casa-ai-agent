# NIST citations CASA may use

The standards skill allows a section-level citation only if it appears here. Anything not
listed is cited at document level or not at all. Every entry below was checked against the
published PDF text on 2026-10-05 (`[verified]`), except where marked.

## NIST SP 800-92, Guide to Computer Security Log Management (September 2006)

Document-level citation: `[NIST SP 800-92]`.

| Citation | Title | Status |
|---|---|---|
| §2 | Introduction to Computer Security Log Management | [verified] |
| §3 | Log Management Infrastructure | [verified] |
| §4 | Log Management Planning | [verified] |
| §4.2 | Establish Logging Policies | [verified] |
| §5 | Log Management Operational Processes | [verified] |
| §5.1 | Configure Log Sources | [verified] |
| §5.2 | Analyze Log Data | [verified] |
| §5.3 | Respond to Identified Events | [verified] |
| §5.4 | Manage Long-Term Log Data Storage | [verified] |

Note: §4 is planning and §5 is the operational processes, including analysis. A Revision 1
draft, *Cybersecurity Log Management Planning Guide*, was released for comment in 2023; its
status and numbering are not recorded here. Do not cite it by section.

## NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile (April 2025)

Document-level citation: `[NIST SP 800-61r3]`. Rev. 3 supersedes Rev. 2 (2012). Rev. 2
section numbers such as "§3.2.4" do not exist in Rev. 3 and must not appear.

| Citation | Title | Status |
|---|---|---|
| §2 | Incident Response as Part of Cybersecurity Risk Management | [verified] |
| §2.1 | Incident Response Life Cycle Model | [verified] |
| §2.2 | Incident Response Roles and Responsibilities | [verified] |
| §2.3 | Incident Response Policies, Processes, and Procedures | [verified] |
| §3 | CSF 2.0 Community Profile for Cyber Incident Risk Management | [verified] |
| §3.1 | Preparation and Lessons Learned (Govern, Identify, Protect functions) | [verified] |
| §3.2 | Incident Response (Detect, Respond, Recover functions) | [verified] |

Within §3, point at the CSF 2.0 subcategory the recommendation sits under (for example
"SP 800-61r3 §3.2, DE.AE-03") rather than inventing a deeper section number.

## NIST AI RMF 1.0, Artificial Intelligence Risk Management Framework (NIST AI 100-1, January 2023)

Document-level citation: `[NIST AI RMF 1.0]`.

| Citation | Content | Status |
|---|---|---|
| Part 1 §3.4 | Accountable and Transparent (trustworthiness characteristic) | [verified] |
| Part 1 §3.5 | Explainable and Interpretable (trustworthiness characteristic) | [verified] |
| MEASURE 2.8 | "Risks associated with transparency and accountability – as identified in the MAP function – are examined and documented." | [verified] |
| MEASURE 2.9 | "The AI model is explained, validated, and documented, and AI system output is interpreted within its context – as identified in the MAP function – to inform responsible use and governance." | [verified] |
| MAP 2.3 | Scientific integrity and TEVV considerations (not explainability; do not cite it for that) | [verified] |

## NIST CSF 2.0 (NIST CSWP 29, February 2024)

Cite by subcategory ID from `csf-2.0.json`, whose IDs and outcome statements are the official
CPRT text (for example `[NIST CSF 2.0, DE.AE-03]`). CSF 1.1 IDs such as `PR.AC-*`, `RS.AN-01`,
`DE.CM-04` and `ID.AM-06` are withdrawn and must not appear.

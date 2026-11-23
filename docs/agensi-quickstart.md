# Start with CASA Free or CASA Pro

| You have | Start here | You get |
| --- | --- | --- |
| A security alert to investigate | [CASA Free: SOC Triage Pack](https://www.agensi.io/skills/casa-free-soc-triage-pack) | A short analyst brief with citations, confidence, and a next evidence request |
| A Sigma rule or Wazuh XML to review | [CASA Pro: Detection Engineering for Wazuh](https://www.agensi.io/skills/casa-pro-detection-engineering-for-wazuh), $9.99 one time | A rule draft or review, a test plan, an alert budget, and rollout evidence to collect |

Connect your agent through [Agensi](https://www.agensi.io/docs/mcp-setup)
and use either pack by its listing name. The example below uses invented data.
Each pack can be used independently.

## Try a sample alert in CASA Free

Paste this into your connected agent:

> Use **CASA Free: SOC Triage Pack** on the synthetic alert below. Give me a short
> brief. Cite the fields you used and identify the one piece of evidence that
> would establish live endpoint collection.

```json
{
  "scenario": "Synthetic demonstration of a benign support file creation",
  "alert_id": "demo-filecreate-01",
  "rule": {
    "id": "110110",
    "description": "Support utility created support-check.txt"
  },
  "event": {
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 11,
    "target_filename": "C:\\ProgramData\\SupportCheck\\Work\\support-check.txt"
  },
  "coverage_note": "The supplied example Sysmon configuration excludes the working folder."
}
```

**What to expect.** A brief should describe the supplied test alert, cite its
rule and file path, and flag live endpoint collection as unverified. A useful
next check is to find a raw FileCreate record in the effective pilot setup
and correlate it to the decoded alert. This example contains one synthetic
alert and no incident evidence.

## Use CASA Pro on a rule

Paste your own Sigma rule or Wazuh XML into your connected agent. For the
fictional example, the rule should match the exact support-tool write to
`support-check.txt`. A proposed Sysmon FileCreate exclusion covers
`C:\ProgramData\SupportCheck\Work\`, so endpoint coverage needs review even if
the rule matches a fixture.

> Use **CASA Pro: Detection Engineering for Wazuh** to review my rule for
> Wazuh 4.14.9. Cite the decoded fields and parent rule, read the supplied
> Sysmon config if available, and give me an exact positive, an unrelated
> negative, and a `.bak` near miss. Separate expected and observed results.

<details>
<summary>Copy the fictional Sigma rule and Sysmon config</summary>

**rule.yml**

```yaml
title: Fictional Support Utility Creates a Check File
id: 2fd271af-7262-42e9-8581-72168f491207
status: test
description: A benign FileCreate test for a fictional support utility.
author: Kyle Versluis
logsource:
  category: file_event
  product: windows
detection:
  selection:
    Image|endswith: '\SupportCheck\support-tool.exe'
    TargetFilename: 'C:\ProgramData\SupportCheck\Work\support-check.txt'
  condition: selection
level: medium
```

**sysmonconfig.xml**

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <FileCreate onmatch="include">
      <Image condition="end with">\SupportCheck\support-tool.exe</Image>
    </FileCreate>
    <FileCreate onmatch="exclude">
      <TargetFilename condition="begin with">C:\ProgramData\SupportCheck\Work\</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

</details>

You can start with pasted inputs. Supply the Wazuh version, relevant Sysmon
config, decoded event, or scratch transcript as available. Your engineer
runs any scratch tests and confirms the real Event 11, rule match, and rollout
evidence on the pilot. When an alert exists, hand its excerpt to CASA Free.

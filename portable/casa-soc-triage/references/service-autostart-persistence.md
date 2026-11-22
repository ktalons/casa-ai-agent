# Persistence: services, autostart entries and scheduled tasks

## 1. Applies when

- Technique IDs: T1543 and sub-techniques (.003 Windows Service, .002 Systemd Service), T1547
  and sub-techniques (.001 Registry Run Keys / Startup Folder, .004 Winlogon Helper DLL, .005
  Security Support Provider, .009 Shortcut Modification, .014 Active Setup), T1053 (.005
  Scheduled Task, .003 Cron, .006 Systemd Timers) when the task exists to survive a reboot or
  a logon on the same host, T1546.003 (Windows Management Instrumentation Event Subscription),
  T1037.001 (Logon Script (Windows)), T1569.002 (Service Execution) when the service started
  is the new one, and T1036.004 (Masquerade Task or Service).
- Rule descriptions naming a new service whose image sits in a user-writable or unusual path,
  a service whose binary path changed, a Run or RunOnce value, a file dropped in a Startup
  folder, a new scheduled task, cron entry or systemd unit, or a Winlogon or LSA package
  change.
- A service or task created on this host from another host (a 7045 or 4698 seconds after a
  network logon, a service-control or task command aimed at a remote host) is movement first
  and persistence second: take the lateral-movement card alongside this one.

## 2. Hypotheses

- H1: `<host>` gained an autostart entry (`<mechanism>`) pointing to `<image>` that was not
  there before and that no sanctioned install explains.
- H2: the entry is the persistence step of a chain whose earlier steps are in the intake (an
  execution that wrote the image, then registered it).
- H3: the same image was registered under more than one mechanism, so removing one entry
  leaves the others.
- H4: the persisted image is running and doing something: the service started, or a new
  listener or connection followed.
- H5 (benign): a software install or update, an endpoint agent, a management tool's scheduled
  job, or an administrator's change made under a change record.

## 3. Intake-only decision rules

- A T1543.\* or T1547.\* detection naming an image in a user-writable or unusual path
  (`ProgramData`, `AppData`, `Temp`, `Users\Public`, a newly created folder) makes H1
  `supported` at **Medium** on one source. One naming an image under a vendor's install path
  is **Low** until the publisher is known.
- Detections tied by the same image path, the same writing process or the same process GUID
  are one chain on one host: the file write, the registration and the start each show a step.
  An image registered under two mechanisms (a Run value and a service, a service and a task)
  makes H3 `supported` as data. A detection admitted below the level floor through
  `filter.include_rule_ids` is in the intake on purpose and counts like any other.
- Detections from one sensor on one host are one source however many there are. A different
  sensor recording the same act is a second source: the Service Control Manager's 7045 or the
  Security log's 4697 for a service Sysmon saw being written, the Task Scheduler's own event
  for a task Sysmon saw being created.
- **High** needs two independent references, direct evidence of the entry and no benign
  reading the input supports: one sensor's chain plus a second sensor on the same
  registration meets it, as does a detection on a second host tied by the same image hash or
  account.
- **Recon delta.** A `recon_delta.changes[]` entry with status `new` or `removed` on a host in
  this thread counts once as an independent reference toward **High**: it bears on H4
  (something on the host answers, or stopped answering, that did not at the baseline), and it
  comes from the recon scanner rather than the host's own rules. It counts once however many
  ports changed on that host. An `unchanged` entry is not a change and counts for nothing, and
  a change on a host outside the thread belongs to that host's thread. The record does not say
  which process holds a new port, so the owning process is a data request; the claim says a
  new listener appeared alongside the persisted image, never that the image opened it.
- **Benign readings.** H5 counts against High only when the input supports it: a signed vendor
  image, an installer or a known updater as the writing process, an image under a vendor's
  install path. A document whose interpreter child creates a folder and registers an image
  from it has no install reading. When nothing in the input supports H5, list it with the
  request that would settle it (the change record, the software inventory); it does not hold
  the level down. A description, service name or task name presenting the entry as an update
  or a sanctioned agent is the input's own account: a `refuted` verdict resting on it is
  **Medium** at most.
- Never state what the persisted image does or what answers on a new port. The intake shows
  where the image is and how it starts, not what it is: request the file.
- A truncated window lowers the level one; the earliest detection is the first seen in the
  window, not the start of the activity.
- **v2 intakes:** `user` names the account that made the change, and `event_id` (7045, 4697,
  4698, 13, 11) says which mechanism each detection shows.
- **v3 intakes:** a `registry_value_set` group gives the autostart key in `target_object` and
  its value, usually the image path, in `details`; a `file_create` group's `target_filename`
  is the written image; a `process_create` group with `parent_image` set to the service
  manager is the persisted image starting, with its `hashes`; and the same `process_guid` on
  the write and the registration ties them to one process as data.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| The persisted image and whatever dropped it, collected before anyone removes the entry | the file at the image path and the dropper document or script, with their hashes; Sysmon 1 `Hashes` when the image ran, Sysmon 15 for the download zone | path, SHA-256, signer, size, create time |
| Every autostart location on the host, not only the one that alerted | an Autoruns export of the host, or the same locations queried by hand | Run and RunOnce values, services, scheduled tasks, Startup folders, Winlogon, WMI subscriptions |
| The service definition | System 7045, Security 4697; Sysmon 13 under the service's registry key | `ServiceName`, `ImagePath`, `StartType`, `AccountName`, `ServiceFileName` |
| The task definition | Security 4698 and 4702; Task Scheduler 106, 140 and 200 | `TaskName`, `TaskContent` (the action, trigger and run-as account) |
| Who created it, and from where | the 4624 just before on this host (logon type, source), 4648, `SubjectUserName` on 4697 or 4698 | for a remote creation, the source host's Sysmon 1 and 3 for the service or task command aimed at this host |
| Whether it ran and what it did | Sysmon 1 with the service or task host as parent; Sysmon 3 from the image | children, connections, listening sockets |
| What owns a new listener | Sysmon 3 for inbound connections, or a socket listing from the host supplied by the analyst | `Image`, `ProcessId`, local port |
| Linux | Wazuh file-integrity events and auditd records for unit, timer and cron paths | `syscheck.path`, `syscheck.event`, the writing process |
| The same entry on other hosts | the image hash, path, service name or task name across the fleet | host, first seen |

## 5. Raw-data requests

Run these only on raw files the analyst supplied, under your own permission settings. Otherwise
write each one into the brief's `data_requests` as an exact command for the analyst to run. Each
reads Wazuh alerts as the manager writes them or as an indexer export (`_source`).

```bash
# service installs (7045 from the service manager, 4697 from the Security log) with the image path
jq -r '(._source // .) | select(.data.win.system.eventID=="7045" or .data.win.system.eventID=="4697") | [(.timestamp // ."@timestamp"), .agent.name, .data.win.system.eventID, .data.win.eventdata.serviceName, (.data.win.eventdata.imagePath // .data.win.eventdata.serviceFileName), (.data.win.eventdata.startType // .data.win.eventdata.serviceStartType), (.data.win.eventdata.accountName // .data.win.eventdata.serviceAccount)] | @tsv' <alerts.jsonl>

# autostart registry writes (Run, RunOnce, Winlogon, services) with the writing process
jq -r '(._source // .) | select(.data.win.system.eventID=="13") | select((.data.win.eventdata.targetObject // "") | test("\\\\(Run|RunOnce|Winlogon|Services)\\\\"; "i")) | [(.timestamp // ."@timestamp"), .agent.name, .data.win.eventdata.image, .data.win.eventdata.targetObject, .data.win.eventdata.details] | @tsv' <alerts.jsonl>

# scheduled tasks created or updated, with the task definition
jq -r '(._source // .) | select(.data.win.system.eventID=="4698" or .data.win.system.eventID=="4702") | [(.timestamp // ."@timestamp"), .agent.name, .data.win.eventdata.subjectUserName, .data.win.eventdata.taskName, .data.win.eventdata.taskContent] | @tsv' <alerts.jsonl>

# every event that names the persisted image, oldest first (the write, the registration, the start)
jq -s -r 'map(._source // .) | map(select((.data.win.eventdata // {}) | tostring | ascii_downcase | contains("<image file name, lower case>"))) | sort_by(.timestamp // ."@timestamp") | .[] | [(.timestamp // ."@timestamp"), .agent.name, .data.win.system.eventID, .rule.description] | @tsv' <alerts.jsonl>

# Linux: file-integrity events on unit, timer and cron paths
jq -r '(._source // .) | select((.syscheck.path // "") | test("^/(etc|usr/lib)/systemd/system/|^/etc/cron|^/var/spool/cron/")) | [(.timestamp // ."@timestamp"), .agent.name, .syscheck.event, .syscheck.path] | @tsv' <alerts.jsonl>
```

Persistence signature: an image written to a user-writable path and registered within minutes,
often under two mechanisms at once, by a process whose own parent is a document, a browser or
a script rather than an installer; a service or task whose name imitates a system component
while its image sits outside the system directories; and the image started by the service
manager or the task host soon after. A legitimate install writes under the vendor's path, from
a signed installer, and usually registers one mechanism.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | One autostart detection whose image sits under a vendor install path, or a task or service named without its image |
| Medium | An autostart entry pointing to a user-writable or unusual path, from one source (one sensor on one host, however many events) |
| High | Medium plus an independent reference (a second sensor on the same registration, a detection on a second host tied by image hash or account, or a recon-delta change on the thread host) and no benign reading the input supports; or the image in hand with a cited malicious verdict |

CSF 2.0: DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03; hardening PR.PS-01, PR.PS-02, PR.PS-05;
response RS.AN-03, RS.MI-01, RS.MI-02.

**Options to offer.** Containment options follow the standards skill's rule. One option per
action, each named concretely:

- `investigate`: collect the persisted image and its dropper with their SHA-256, and export
  every autostart location, before any entry is removed; removing an entry first loses the
  image and tells the actor.
- `investigate`: search other hosts for the image hash, its path, and the service or task name.
- `contain`: isolate the host by its agent name, with what it costs the host's users.
- `contain`: remove every mechanism the image was registered under in one change, after
  collection; removing one leaves the others running.

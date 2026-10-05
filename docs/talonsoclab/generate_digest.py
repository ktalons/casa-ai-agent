#!/usr/bin/env python3
"""SOC digest + CASA intake builder (TalonSocLab data plane).

Pulls two streams into a human-readable digest AND a structured intake artifact:
  1. Detections — high-severity Wazuh alerts from the indexer (OpenSearch).
  2. Attack surface — the newest recon delta(s) from the triage queue.

Division of labor (this is the architecture — don't blur it):
  * THIS script (TalonSocLab) is deterministic infrastructure. It collects, filters,
    cites, and emits artifacts. It does NOT reason and does NOT decide.
  * CASA (github.com/ktalons/casa-ai-agent) is the separate reasoning plane, a Claude Code
    plugin whose specialist agents consume the {date}-intake.json written here and produce
    explainable, NIST-aligned, human-in-the-loop analysis. THAT is the reasoning layer, not
    an LLM call buried in this file.

Outputs per run:
  * {date}-digest.md   — deterministic human-readable digest (no LLM).
  * {date}-intake.json — structured handoff CASA reasons over: talonsoclab.soc-intake/v2
                         (window, filter, truncation, pipeline liveness, per-alert correlation
                         fields, structured recon delta). --schema v1 emits the frozen v1 shape.

--alerts-file replays recorded attack data for repeatable evals: feed the same intake
to CASA and measure its reasoning. In replay the window is anchored to the data, not to
now, so old recordings still validate. stdlib only — no pip install, same as diff.py.

The optional --summarize / DIGEST_LLM path is a STANDALONE convenience (a quick inline
Claude rewrite of the markdown). It is NOT the CASA integration and does no agentic
reasoning — the real reasoning layer is CASA consuming the intake JSON.
"""
import argparse
import json
import math
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

SEV_LABEL = [(15, "critical"), (12, "high"), (7, "medium"), (0, "low")]
CONSUMER = "casa-ai-agent (github.com/ktalons/casa-ai-agent)"
NOTE = "Deterministic intake. Reasoning happens in CASA, not here."
ISO_SECONDS = "%Y-%m-%dT%H:%M:%SZ"
V1_KEYS = ("level", "description", "rule_id", "agent", "mitre", "timestamp")


def level_label(level: int) -> str:
    for floor, name in SEV_LABEL:
        if level >= floor:
            return name
    return "low"


def utc_now(ceil: bool = False) -> datetime:
    """Now, at whole seconds: floored by default, or rounded up for a window end so a
    record stamped a few milliseconds ago still falls inside the window."""
    dt = datetime.now(timezone.utc)
    return ceil_second(dt) if ceil else dt.replace(microsecond=0)


def ceil_second(dt: datetime) -> datetime:
    return dt if dt.microsecond == 0 else dt.replace(microsecond=0) + timedelta(seconds=1)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO_SECONDS)


def parse_ts(text: str):
    """Wazuh @timestamp ('2026-07-20T02:19:47.418Z') to an aware datetime, or None."""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def parse_lookback(text: str) -> int:
    """'24h' or '3d' (the indexer's now-<lookback> form) to whole hours."""
    m = re.fullmatch(r"\s*(\d+)\s*([hd])\s*", text)
    if not m:
        sys.exit(f"[digest] DIGEST_LOOKBACK must look like 24h or 3d, got {text!r}")
    n, unit = int(m.group(1)), m.group(2)
    return n if unit == "h" else n * 24


def first(*values):
    for v in values:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


# ─────────────────────────── detections (Wazuh) ───────────────────────────
def indexer_search(url, user, password, body: dict) -> dict:
    """One _search against wazuh-alerts-*.

    Self-signed certs are expected on a single-node lab indexer, so verification is
    disabled deliberately here — do NOT copy this ssl context into anything internet-facing.
    """
    req = urllib.request.Request(
        f"{url.rstrip('/')}/wazuh-alerts-*/_search",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + b64encode(f"{user}:{password}".encode()).decode(),
        },
        method="POST",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_alerts_from_indexer(url, user, password, min_level, lookback, cap):
    """Alerts with level>=min_level in the lookback window, newest first, at most cap.

    Returns (alerts, total) where total is how many matched before the cap, so the
    intake can say whether the cap cut the list.
    """
    body = {
        "size": cap,
        "track_total_hits": True,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": f"now-{lookback}"}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
    }
    resp = indexer_search(url, user, password, body)
    hits = resp.get("hits", {}).get("hits", [])
    total = resp.get("hits", {}).get("total", {})
    total = total.get("value", len(hits)) if isinstance(total, dict) else int(total or len(hits))
    return [normalize_alert(h.get("_source", {})) for h in hits], total


def fetch_pipeline_health(url, user, password, lookback) -> dict:
    """Is the pipeline alive? Counted over ALL alert levels in the window, so a quiet
    high-severity window can be told apart from a collector that stopped."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{lookback}"}}}]}},
        "aggs": {
            "agents": {"cardinality": {"field": "agent.name"}},
            "last": {"max": {"field": "@timestamp"}},
        },
    }
    try:
        resp = indexer_search(url, user, password, body)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"[digest] pipeline health query failed: {e}", file=sys.stderr)
        return {"collector_ok": False, "agents_reporting": 0, "last_event_seen": None}
    aggs = resp.get("aggregations", {})
    last = aggs.get("last", {}).get("value_as_string")
    last_dt = parse_ts(last) if last else None
    return {
        "collector_ok": True,
        "agents_reporting": int(aggs.get("agents", {}).get("value", 0) or 0),
        "last_event_seen": last_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{last_dt.microsecond // 1000:03d}Z" if last_dt else None,
    }


def normalize_alert(src: dict) -> dict:
    """One detection: the six v1 fields plus the v2 correlation fields (all nullable)."""
    rule = src.get("rule", {}) or {}
    agent = src.get("agent", {}) or {}
    data = src.get("data", {}) or {}
    win = data.get("win", {}) or {}
    eventdata = win.get("eventdata", {}) or {}
    system = win.get("system", {}) or {}
    mitre = rule.get("mitre", {}) or {}
    timestamp = src.get("@timestamp") or src.get("timestamp") or "?"
    rule_id = str(rule.get("id", "?"))
    agent_name = agent.get("name", "?")
    return {
        "level": int(rule.get("level", 0)),
        "description": rule.get("description", "?"),
        "rule_id": rule_id,
        "agent": agent_name,
        "mitre": list(mitre.get("id") or []),
        "timestamp": timestamp,
        "alert_id": first(src.get("id")) or f"{timestamp}|{rule_id}|{agent_name}",
        "src_ip": first(data.get("srcip"), eventdata.get("ipAddress"), eventdata.get("IpAddress")),
        "dst_ip": first(data.get("dstip"), eventdata.get("destinationIp"), eventdata.get("DestinationIp")),
        "user": first(data.get("srcuser"), data.get("dstuser"),
                      eventdata.get("targetUserName"), eventdata.get("TargetUserName")),
        "event_id": first(str(system.get("eventID") or ""), str(system.get("eventId") or "")),
        "tactic": list(mitre.get("tactic") or []),
        "groups": list(rule.get("groups") or []),
    }


def to_v1(alert: dict) -> dict:
    return {k: alert[k] for k in V1_KEYS}


def load_alerts_file(path: Path) -> list:
    """Offline mode: read recorded alerts (JSON list or JSONL) for repeatable evals."""
    text = path.read_text()
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else data.get("hits", {}).get("hits", [])
    except json.JSONDecodeError:
        records = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    return [normalize_alert(rec.get("_source", rec)) for rec in records]


def replay_select(alerts: list, min_level: int, cap: int):
    """Apply the live query's guarantees to a replay file: level floor, newest first,
    no duplicate alert ids, at most cap. Returns (alerts, truncated)."""
    kept, seen = [], set()
    for a in sorted(alerts, key=lambda a: parse_ts(a["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc), reverse=True):
        if a["level"] < min_level or a["alert_id"] in seen:
            continue
        seen.add(a["alert_id"])
        kept.append(a)
    return kept[:cap], len(kept) > cap


# ─────────────────────────── attack surface (recon) ───────────────────────────
RUN_FILE_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T\d{6}Z_(baseline|delta)\.md$")


def latest_recon(triage_dir: Path):
    """Newest delta (or baseline) markdown, the newest baseline date, and the hosts the
    delta lists as new subdomains."""
    deltas = sorted(triage_dir.glob("*_delta.md"))
    baselines = sorted(triage_dir.glob("*_baseline.md"))
    baseline = None
    if baselines:
        m = RUN_FILE_RE.match(baselines[-1].name)
        if m:
            baseline = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    if deltas:
        text = deltas[-1].read_text().strip()
        return text, baseline, new_subdomains(text)
    if baselines:
        return baselines[-1].read_text().strip(), baseline, []
    return "_No recon runs found in the triage queue yet._", baseline, []


def new_subdomains(delta_md: str) -> list:
    """Hosts under the '## New subdomains' heading of a diff.py delta."""
    hosts, in_section = [], False
    for line in delta_md.splitlines():
        if line.startswith("## "):
            in_section = line.startswith("## New subdomains")
            continue
        m = re.match(r"^- \[[ x]\] `([^`]+)`\s*$", line)
        if in_section and m:
            hosts.append(m.group(1).strip().lower())
    return hosts


def load_httpx(recon_dir: Path) -> dict:
    """host -> sorted list of (port, proto) from the latest run's httpx.jsonl, if any."""
    path = recon_dir / "latest" / "httpx.jsonl"
    listeners = {}
    if not path.exists():
        return listeners
    for ln in path.read_text().splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        url = rec.get("url") or ""
        parts = urlsplit(url) if url else None
        host = (rec.get("host") or (parts.hostname if parts else None) or rec.get("input") or "").lower()
        if not host:
            continue
        port = rec.get("port") or (parts.port if parts else None) or (443 if parts and parts.scheme == "https" else 80)
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        listeners.setdefault(host, set()).add((port, "tcp"))
    return {h: sorted(p) for h, p in listeners.items()}


def recon_changes(new_hosts: list, listeners: dict) -> list:
    """One change per new host and observed port. A host with no live probe gets port 0:
    new in enumeration, no listener observed."""
    changes, seen = [], set()
    for host in new_hosts:
        for port, proto in listeners.get(host) or [(0, "tcp")]:
            key = (host, port, proto)
            if key in seen:
                continue
            seen.add(key)
            changes.append({"host": host, "port": port, "proto": proto, "status": "new"})
    return changes


# ─────────────────────────── rendering ───────────────────────────
def render_detections(alerts: list) -> str:
    if not alerts:
        return "- No alerts at or above the severity floor in the window. _(verify the pipeline is live.)_"
    buckets = {"critical": [], "high": [], "medium": [], "low": []}
    for a in alerts:
        buckets[level_label(a["level"])].append(a)
    lines = []
    for sev in ("critical", "high", "medium", "low"):
        items = buckets[sev]
        if not items:
            continue
        lines.append(f"- **{len(items)} {sev}-severity** "
                     f"({'rolled up' if sev in ('medium', 'low') else 'see detail'}):")
        for a in items[:8 if sev in ("critical", "high") else 0]:
            mitre = f" [{', '.join(a['mitre'])}]" if a["mitre"] else ""
            lines.append(f"  - `{a['agent']}` — {a['description']} "
                         f"(rule {a['rule_id']}, level {a['level']}){mitre}")
    return "\n".join(lines)


def build_intake_v1(date_str, alerts, recon_text) -> dict:
    """The frozen v1 handoff, kept for rollback (--schema v1)."""
    return {
        "schema": "talonsoclab.soc-intake/v1",
        "generated": date_str,
        "source": "talonsoclab",
        "consumer": CONSUMER,
        "detections": [to_v1(a) for a in alerts],
        "recon_delta": recon_text,
        "note": NOTE,
    }


def build_intake_v2(now, window_start, window_end, lookback_hours, min_level, cap,
                    truncated, pipeline, alerts, recon_md, baseline, changes) -> dict:
    """The structured handoff CASA reasons over. Deterministic collection only —
    no analysis, no scoring, no decisions. CASA's agents add all of that."""
    return {
        "schema": "talonsoclab.soc-intake/v2",
        "generated": iso(now),
        "source": "talonsoclab",
        "consumer": CONSUMER,
        "window": {"start": iso(window_start), "end": iso(window_end), "lookback_hours": lookback_hours},
        "filter": {"min_level": min_level, "cap": cap, "order": "newest_first"},
        "truncated": truncated,
        "pipeline": pipeline,
        "detections": alerts,
        "recon_delta": {"markdown": recon_md, "baseline": baseline, "changes": changes},
        "note": NOTE,
    }


def build_template_digest(date_str, detections_md, recon_md) -> str:
    return (
        f"# Daily digest — {date_str}\n\n"
        "_Built by the TalonSocLab digest collector from two sources: the Wazuh alert "
        "stream and the recon diff output. Deterministic summary — every item links back "
        "to the raw record. Agentic analysis is CASA's job; this is its intake._\n\n"
        "## Attack surface (recon)\n"
        f"{recon_md}\n\n"
        "## Detections (Wazuh)\n"
        f"{detections_md}\n\n"
        "## Suggested focus\n"
        "1. Triage the newest recon delta in `triage/` — is anything actually exposed?\n"
        "2. Confirm the top detection isn't your own admin activity before escalating.\n\n"
        "---\n"
        "_Sources: `data/recon/<run>/`, Wazuh indexer query "
        "`rule.level>=12 AND @timestamp>now-24h`._\n"
    )


def summarize(date_str, detections_md, recon_md) -> str:
    """Optional inline LLM rewrite. Off unless DIGEST_LLM=1 and a key is present.

    STANDALONE CONVENIENCE ONLY — this is a one-shot Claude rewrite of the digest
    markdown for quick reading. It is NOT the CASA integration and does no agentic
    reasoning; the model only ever sees data already filtered + cited above. The real
    reasoning layer is CASA consuming {date}-intake.json. Keep this dumb on purpose."""
    if os.getenv("DIGEST_LLM", "0") != "1":
        return build_template_digest(date_str, detections_md, recon_md)

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("[digest] DIGEST_LLM=1 but ANTHROPIC_API_KEY is empty — "
              "falling back to deterministic template.", file=sys.stderr)
        return build_template_digest(date_str, detections_md, recon_md)

    raw = build_template_digest(date_str, detections_md, recon_md)
    prompt = (
        "You are a SOC shift-lead writing the morning digest. Below is a machine-built "
        "digest of overnight detections and attack-surface changes. Rewrite it to be "
        "tighter and prioritized. RULES: invent nothing; every claim must trace to the "
        "input; keep all rule IDs, hostnames, and source links; if something is "
        "ambiguous say so rather than guessing. Output markdown only.\n\n"
        f"---\n{raw}\n---"
    )
    body = json.dumps({
        "model": os.getenv("DIGEST_LLM_MODEL", "claude-haiku-4-5-20251001"),
        "max_tokens": 1500,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.loads(resp.read())
        return "".join(b.get("text", "") for b in out.get("content", [])) or raw
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"[digest] LLM call failed ({e}); using deterministic template.", file=sys.stderr)
        return raw


def main():
    ap = argparse.ArgumentParser(
        description="Build the deterministic SOC digest + CASA intake artifact.")
    ap.add_argument("--triage-dir", default="triage")
    ap.add_argument("--recon-dir", default="data/recon",
                    help="Recon output root; <recon-dir>/latest/httpx.jsonl resolves ports "
                         "for new subdomains in the v2 recon delta.")
    ap.add_argument("--out-dir", default="digest")
    ap.add_argument("--alerts-file", help="Offline: read alerts from this JSON/JSONL "
                                          "instead of the live indexer (for evals).")
    ap.add_argument("--schema", choices=("v2", "v1"), default="v2",
                    help="Intake contract to emit (default v2; v1 is the frozen original).")
    ap.add_argument("--summarize", action="store_true",
                    help="Inline LLM rewrite of the markdown (standalone convenience, "
                         "NOT the CASA integration). Equivalent to DIGEST_LLM=1.")
    ap.add_argument("--stdout", action="store_true", help="Print digest instead of writing files.")
    args = ap.parse_args()
    if args.summarize:
        os.environ["DIGEST_LLM"] = "1"

    min_level = int(os.getenv("DIGEST_MIN_LEVEL", "12"))
    lookback = os.getenv("DIGEST_LOOKBACK", "24h")
    cap = int(os.getenv("DIGEST_CAP", "200"))
    lookback_hours = parse_lookback(lookback)

    if args.alerts_file:
        alerts, truncated = replay_select(load_alerts_file(Path(args.alerts_file)), min_level, cap)
        stamps = [t for t in (parse_ts(a["timestamp"]) for a in alerts) if t]
        # Replay: anchor the window to the recording so old data still validates.
        now = utc_now(ceil=True)
        window_end = ceil_second(max(stamps)) if stamps else now
        window_start = window_end - timedelta(hours=lookback_hours)
        if stamps and min(stamps) < window_start:
            window_start = min(stamps)
            lookback_hours = max(1, math.ceil((window_end - window_start).total_seconds() / 3600))
        pipeline = {
            "collector_ok": True,
            "agents_reporting": len({a["agent"] for a in alerts}),
            "last_event_seen": max(a["timestamp"] for a in alerts) if alerts else None,
        }
    else:
        url = os.getenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
        user = os.getenv("WAZUH_INDEXER_USER", "admin")
        password = os.getenv("WAZUH_INDEXER_PASS", "")
        if not password:
            print("[digest] WAZUH_INDEXER_PASS is empty — set it in .env or use "
                  "--alerts-file for offline mode.", file=sys.stderr)
            sys.exit(2)
        # The window must contain the query's own range: start is taken before the query
        # and end after it, both at whole seconds, so no alert can fall outside it.
        window_start = utc_now() - timedelta(hours=lookback_hours)
        try:
            alerts, total = fetch_alerts_from_indexer(url, user, password, min_level, lookback, cap)
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"[digest] could not reach indexer: {e}", file=sys.stderr)
            sys.exit(1)
        truncated = total > cap
        pipeline = fetch_pipeline_health(url, user, password, lookback)
        now = utc_now(ceil=True)
        window_end = now

    date_str = now.strftime("%Y-%m-%d")
    detections_md = render_detections(alerts)
    recon_md, baseline, new_hosts = latest_recon(Path(args.triage_dir))
    changes = recon_changes(new_hosts, load_httpx(Path(args.recon_dir)))
    digest = summarize(date_str, detections_md, recon_md)
    if args.schema == "v1":
        intake = build_intake_v1(date_str, alerts, recon_md)
    else:
        intake = build_intake_v2(now, window_start, window_end, lookback_hours, min_level, cap,
                                 truncated, pipeline, alerts, recon_md, baseline, changes)

    if args.stdout:
        print(digest)
        return
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    digest_path = out_dir / f"{date_str}-digest.md"
    intake_path = out_dir / f"{date_str}-intake.json"
    digest_path.write_text(digest)
    intake_path.write_text(json.dumps(intake, indent=2) + "\n")
    print(f"[digest] wrote {digest_path} + {intake_path} ({len(alerts)} alerts, "
          f"schema={args.schema}, mode={'llm' if os.getenv('DIGEST_LLM') == '1' else 'template'}) "
          f"— hand the intake to CASA for reasoning")


if __name__ == "__main__":
    main()

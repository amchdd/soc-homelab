"""Filter current-run, allowlisted lab evidence and enforce provenance/hashes."""
import argparse
import hashlib
import json
from pathlib import Path
from common import RULES, compose, json_lines, utc_timestamp


def select_alerts(rows, since, run_id, changes):
    since = utc_timestamp(since)
    selected = []
    seen = set()
    for row in rows:
        rule = row.get("rule", {})
        if not isinstance(rule, dict):
            raise ValueError("Malformed rule object")
        rule_id = str(rule.get("id"))
        if rule_id not in RULES:
            continue
        stamp = utc_timestamp(row["timestamp"])
        if stamp < since:
            continue
        agent = row.get("agent", {})
        data = row.get("data", {})
        origin = RULES[rule_id][1]
        if origin == "synthetic":
            if agent.get("name") != "soc-manager" or data.get("lab") != "soc-homelab":
                continue
            if data.get("origin") != "synthetic" or data.get("run_id") != run_id:
                continue
        elif origin == "controlled_live_ssh":
            if agent.get("name") != "soc-endpoint" or data.get("dstuser") != "labuser":
                continue
            if data.get("srcip") != "127.0.0.1":
                continue
        else:
            fim = row.get("syscheck", {})
            expected = changes.get(fim.get("path"))
            if agent.get("name") != "soc-endpoint" or not expected:
                continue
            action = {"100105": "modified", "100113": "added", "100114": "deleted"}[rule_id]
            if fim.get("event") != action:
                continue
            for key, value in expected.items():
                if fim.get(key) != value:
                    raise ValueError(f"FIM hash mismatch: {fim.get('path')} / {key}")
        item = {
            "timestamp": row["timestamp"], "rule": rule,
            "agent": {"id": agent["id"], "name": agent["name"]},
            "origin": origin,
        }
        if "data" in row:
            allowed = {"srcip", "srcport", "dstuser", "lab", "origin", "host", "timestamp",
                       "lab_event", "service", "scenario", "run_id", "event_id",
                       "process_name", "command_line", "note"}
            item["data"] = {key: value for key, value in data.items() if key in allowed}
        if origin == "controlled_live_ssh":
            item["full_log"] = row["full_log"]
        if "syscheck" in row:
            allowed = {"path", "mode", "event", "size_before", "size_after",
                       "sha256_before", "sha256_after", "changed_attributes"}
            item["syscheck"] = {key: value for key, value in row["syscheck"].items() if key in allowed}
        identity = row.get("id") or hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
        if identity not in seen:
            seen.add(identity)
            selected.append(item)
    return sorted(selected, key=lambda item: utc_timestamp(item["timestamp"]))


def require_coverage(alerts):
    present = {str(row["rule"]["id"]) for row in alerts}
    missing = set(RULES) - present
    if missing:
        raise ValueError(f"Missing end-to-end evidence: {', '.join(sorted(missing))}")


def export(since, run_id, changes, output):
    raw = compose("exec", "-T", "manager", "cat", "/var/ossec/logs/alerts/alerts.json").stdout
    selected = select_alerts(json_lines(raw), since, run_id, changes)
    require_coverage(selected)
    Path(output).write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in selected), encoding="utf-8", newline="\n")
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--changes", required=True)
    parser.add_argument("--output", default="runtime/alerts.jsonl")
    args = parser.parse_args()
    changes = json.loads(Path(args.changes).read_text(encoding="utf-8"))
    rows = export(args.since, args.run_id, changes, args.output)
    print(f"Exported {len(rows)} current-run lab alerts")


if __name__ == "__main__":
    main()

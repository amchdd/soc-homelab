"""Deterministic, labelled fixtures. No payload is executed."""
import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path


def events(run_id="fixture-reference", timestamp=None):
    stamp = timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    base = {
        "lab": "soc-homelab", "origin": "synthetic", "run_id": run_id,
        "host": "fixture-endpoint", "user": "labuser", "timestamp": stamp,
    }
    rows = [
        base | {"event_id": f"{run_id}-auth-{index}", "lab_event": "authentication_failure",
                "srcip": "192.0.2.10", "service": "ssh", "scenario": "AUTH-JSON"}
        for index in range(8)
    ]
    # UTF-16LE encoding of a benign string; retained exclusively as process data.
    encoded = base64.b64encode("Write-Output 'SOC lab'".encode("utf-16le")).decode("ascii")
    rows.append(base | {
        "event_id": f"{run_id}-proc", "lab_event": "process_creation",
        "process_name": "powershell.exe",
        "command_line": f"powershell.exe -EncodedCommand {encoded}",
        "scenario": "PROC-001", "note": "Fixture only; not executed",
    })
    rows.append(base | {
        "event_id": f"{run_id}-benign-proc", "lab_event": "process_creation",
        "process_name": "powershell.exe", "command_line": "powershell.exe Get-Date",
        "scenario": "CONTROL-PROC",
    })
    rows.append(base | {
        "event_id": f"{run_id}-benign-auth", "lab_event": "authentication_success",
        "srcip": "192.0.2.20", "scenario": "CONTROL-AUTH",
    })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="runtime/events.jsonl")
    parser.add_argument("--run-id", default="fixture-reference")
    parser.add_argument("--append", action="store_true")
    args = parser.parse_args()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a" if args.append else "w", encoding="utf-8", newline="\n") as stream:
        for row in events(args.run_id):
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"11 synthetic events written to {target}")


if __name__ == "__main__":
    main()

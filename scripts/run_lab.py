"""Verify live endpoint telemetry and fixtures; publish only complete snapshots."""
import argparse
import hashlib
import json
import secrets
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from common import ROOT, VERSION, ENGINE_VERSION, MANAGER_IMAGE, compose, write_json
from export_evidence import export
from generate_events import events
from triage import render_report, render_html, verify_manifest
from verify_rules import verify


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(content):
    return hashlib.sha256(content).hexdigest()


def wait_until(check, label, timeout=150):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {label}")


def agent_ready():
    status = compose("exec", "-T", "manager", "/var/ossec/bin/agent_control", "-l", check=False)
    return status.returncode == 0 and any(
        "soc-endpoint" in line and "Active" in line for line in status.stdout.splitlines()
    )


def fim_ready():
    log = compose("exec", "-T", "endpoint", "cat", "/var/ossec/logs/ossec.log", check=False)
    return log.returncode == 0 and "File integrity monitoring scan ended" in log.stdout


def ssh_login(password):
    # stdin keeps the temporary credential out of process arguments and evidence.
    command = (
        "read -r SOC_LAB_PASSWORD; export SOC_LAB_PASSWORD; "
        "export SSH_ASKPASS=/usr/local/bin/lab-askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0; "
        "exec ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no "
        "-o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "
        "labuser@127.0.0.1 'echo SOC_LAB_AUTHORIZED_LOGIN'"
    )
    return compose("exec", "-T", "endpoint", "/bin/sh", "-c", command,
                   input_text=password + "\n", check=False, timeout=20)


def record_manifest(folder, metadata):
    names = ["alerts.jsonl", "rule-tests.json", "triage.md", "report.html", "ssh-auth.log", "fim-changes.json"]
    metadata["artifacts_sha256"] = {name: sha((folder / name).read_bytes()) for name in names}
    if configuration_hashes() != metadata["configuration_sha256"]:
        raise RuntimeError("Source changed during validation; rerun the exercise")
    write_json(folder / "manifest.json", metadata)
    verify_manifest(folder, verify_source=True)


def configuration_hashes():
    inputs = [".gitattributes", "compose.yaml", "config/ossec.conf", "config/agent.conf", "rules/soc_lab.xml",
              "endpoint/Dockerfile", "endpoint/sshd_config", "endpoint/rsyslog.conf",
              "endpoint/start.sh", "endpoint/askpass.sh"]
    inputs += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "scripts").glob("*.py"))]
    return {name: sha((ROOT / name).read_bytes()) for name in inputs}


def run_lab(snapshot=False, keep_running=False):
    source_hashes = configuration_hashes()
    run_id = uuid.uuid4().hex
    started = now()
    runtime = ROOT / "runtime"
    protected = runtime / "protected"
    protected.mkdir(parents=True, exist_ok=True)
    (runtime / "events.jsonl").write_text("", encoding="utf-8", newline="\n")
    output = runtime / "runs" / run_id
    output.mkdir(parents=True)
    modified = protected / f"{run_id}-modified.conf"
    deleted = protected / f"{run_id}-deleted.conf"
    created = protected / f"{run_id}-created.conf"
    baseline = b"scope=soc-lab\nstate=baseline\n"
    changed = b"scope=soc-lab\nstate=authorized-change\n"
    new_content = b"scope=soc-lab\nstate=authorized-create\n"
    modified.write_bytes(baseline)
    deleted.write_bytes(baseline)
    changes = {
        f"/lab/protected/{modified.name}": {"sha256_before": sha(baseline), "sha256_after": sha(changed)},
        f"/lab/protected/{created.name}": {"sha256_after": sha(new_content)},
        # Wazuh 4.14.8 retains the last known digest in sha256_after for deletion.
        f"/lab/protected/{deleted.name}": {"sha256_after": sha(baseline)},
    }
    write_json(output / "fim-changes.json", changes)
    try:
        print("Starting isolated Wazuh manager and Linux endpoint...", flush=True)
        compose("up", "-d", "--build", "--force-recreate", timeout=600)
        wait_until(agent_ready, "active enrolled endpoint")
        wait_until(fim_ready, "endpoint FIM baseline")
        print("Endpoint enrolled; native FIM baseline completed.", flush=True)
        tests = verify(output / "rule-tests.json")
        since = now()
        with (runtime / "events.jsonl").open("a", encoding="utf-8", newline="\n") as stream:
            for row in events(run_id):
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        password = secrets.token_urlsafe(24)
        compose("exec", "-T", "endpoint", "chpasswd", input_text=f"labuser:{password}\n")
        print("Generating eight deliberate SSH password failures and one authorized login...", flush=True)
        for _ in range(8):
            result = ssh_login("deliberately-incorrect-lab-password")
            if result.returncode != 255:
                raise RuntimeError("Expected SSH authentication failure did not occur")
        result = ssh_login(password)
        if result.returncode != 0 or "SOC_LAB_AUTHORIZED_LOGIN" not in result.stdout:
            raise RuntimeError("Authorized SSH login control failed")
        compose("exec", "-T", "endpoint", "usermod", "-L", "labuser")
        raw = compose("exec", "-T", "endpoint", "cat", "/var/log/lab-auth.log").stdout
        lines = [line for line in raw.splitlines()
                 if "password for labuser from 127.0.0.1" in line]
        if sum("Failed password" in line for line in lines) != 8 or sum("Accepted password" in line for line in lines) != 1:
            raise RuntimeError("OpenSSH source log did not confirm the expected 8 failures / 1 success")
        (output / "ssh-auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        modified.write_bytes(changed)
        created.write_bytes(new_content)
        # Both the resolved location and filename are generated inside this lab.
        if deleted.resolve().parent != protected.resolve():
            raise RuntimeError("Refusing deletion outside the lab folder")
        deleted.unlink()
        print("Waiting for current-run SSH, correlation and three native FIM events...", flush=True)
        last_error = None
        alerts = None
        for _ in range(45):
            try:
                alerts = export(since, run_id, changes, output / "alerts.jsonl")
                break
            except ValueError as exc:
                last_error = exc
                time.sleep(2)
        if alerts is None:
            raise RuntimeError(str(last_error))
        metadata = {
            "schema_version": 1, "portfolio_version": VERSION, "engine_version": ENGINE_VERSION,
            "status": "passed", "run_id": run_id, "started_at": started,
            "collection_started_at": since, "completed_at": now(),
            "scope": "isolated_containers", "manager_image": MANAGER_IMAGE,
            "configuration_sha256": source_hashes,
            "endpoint_base_image": "wazuh/wazuh-agent:4.14.8@sha256:32215f51b62b072b9ff010d1c03da4e1f586947aaa686c40b927509fc85855cc",
            "endpoint_image_id": compose("images", "-q", "endpoint").stdout.strip(),
            "ssh_operations": {"failed_passwords": 8, "authorized_logins": 1, "source_ip": "127.0.0.1"},
            "rule_test_count": len(tests), "alert_count": len(alerts),
            "limits": ["No Windows/Sysmon endpoint", "No indexer/dashboard", "No automatic containment"],
        }
        (output / "triage.md").write_text(render_report(alerts, metadata, tests), encoding="utf-8", newline="\n")
        (output / "report.html").write_text(render_html(alerts, metadata, tests), encoding="utf-8", newline="\n")
        record_manifest(output, metadata)
        if snapshot:
            target = ROOT / "evidence"
            target.mkdir(exist_ok=True)
            for name in [*metadata["artifacts_sha256"], "manifest.json"]:
                shutil.copy2(output / name, target / name)
            verify_manifest(target, verify_source=True)
            print("Verified portfolio snapshot saved in evidence/.", flush=True)
        print(f"PASS — {len(tests)} engine cases, 9 detection rules, {len(alerts)} alerts.", flush=True)
        print(f"Report: {output / 'report.html'}", flush=True)
        return output
    except Exception as exc:
        write_json(output / "failure.json", {"run_id": run_id, "status": "failed", "error": str(exc)})
        raise
    finally:
        if not keep_running:
            result = compose("stop", check=False, timeout=90)
            if result.returncode:
                print("Could not stop lab; run docker compose stop.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", action="store_true", help="Replace evidence/ only after complete validation")
    parser.add_argument("--keep-running", action="store_true", help="Leave the isolated lab running for inspection")
    args = parser.parse_args()
    try:
        run_lab(args.snapshot, args.keep_running)
    except Exception as exc:
        print(f"FAIL — {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

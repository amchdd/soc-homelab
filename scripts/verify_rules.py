"""Use separate real Wazuh logtest sessions for each positive/negative case."""
import argparse
import json
import re
from common import ENGINE_VERSION, compose, write_json
from generate_events import events


def ssh_event(success=False, source="127.0.0.1", user="labuser"):
    action = "Accepted" if success else "Failed"
    return f"Sep 28 12:00:00 soc-endpoint sshd[4242]: {action} password for {user} from {source} port 42420 ssh2"


def cases():
    rows = events()
    encoded = rows[8]
    data = [
        ("JSON authentication failure", [rows[0]], "100101"),
        ("PowerShell encoded command", [encoded], "100103"),
        ("PowerShell mixed-case abbreviated option", [encoded | {"command_line": "powershell -eNc AAAA"}], "100103"),
        ("PowerShell Core encoded command", [encoded | {"process_name": "pwsh", "command_line": "pwsh -EncodedCommand AAAA"}], "100103"),
        ("Ordinary PowerShell control", [rows[9]], "100100"),
        ("Successful JSON login control", [rows[10]], "100100"),
        ("Unrelated application control", [encoded | {"lab": "other-app"}], "NOT_LAB"),
        ("Wrong process control", [encoded | {"process_name": "cmd.exe"}], "100100"),
        ("Similar option control", [encoded | {"command_line": "powershell -Encoding UTF8"}], "100100"),
        ("Unlabelled origin control", [encoded | {"origin": "untrusted"}], "NOT_LAB"),
        ("JSON same-source correlation", rows[:8], "100102"),
        ("JSON different-source control", [row | {"srcip": f"192.0.2.{index + 30}"} for index, row in enumerate(rows[:8])], "NO_CORRELATION"),
        ("JSON different-run control", [row | {"run_id": f"separate-{index}"} for index, row in enumerate(rows[:8])], "NO_CORRELATION"),
        ("OpenSSH failure decoding", [ssh_event()], "100110"),
        ("OpenSSH successful login context", [ssh_event(success=True)], "100112"),
        ("Other SSH account control", [ssh_event(user="otheruser")], "NOT_LAB"),
        ("OpenSSH same-source correlation", [ssh_event() for _ in range(8)], "100111"),
        ("OpenSSH different-source control", [ssh_event(source=f"192.0.2.{index + 40}") for index in range(8)], "NO_CORRELATION"),
    ]
    return data


def verify(output):
    results = []
    for name, rows, expected in cases():
        payload = "\n".join(json.dumps(row) if isinstance(row, dict) else row for row in rows) + "\n"
        proc = compose("exec", "-T", "manager", "/var/ossec/bin/wazuh-logtest", input_text=payload, check=False)
        text = proc.stdout + proc.stderr
        matched = re.findall(r"\bid: '(\d+)'", text)
        ready = proc.returncode == 0 and "Completed decoding" in text
        if expected == "NOT_LAB":
            passed = ready and not any(rule.startswith("1001") for rule in matched)
        elif expected == "NO_CORRELATION":
            base_rule = "100110" if isinstance(rows[0], str) else "100101"
            passed = ready and len(matched) == len(rows) and set(matched) == {base_rule}
        else:
            passed = ready and (matched[-1:] == [expected] if len(rows) == 1 else expected in matched)
        results.append({
            "case": name, "input_origin": "synthetic", "expected": expected,
            "matched_rule_ids": matched, "passed": bool(passed), "engine_output": text,
        })
        print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)
    write_json(output, {"engine": f"Wazuh {ENGINE_VERSION}", "results": results})
    if not all(result["passed"] for result in results):
        raise RuntimeError(f"Rule regression failed; inspect {output}")
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="runtime/rule-tests.json")
    args = parser.parse_args()
    verify(args.output)


if __name__ == "__main__":
    main()

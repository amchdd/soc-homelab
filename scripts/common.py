"""Shared paths, version contract and bounded Docker commands."""
import json
import subprocess
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"
ENGINE_VERSION = "4.14.8"
MANAGER_IMAGE = "wazuh/wazuh-manager:4.14.8@sha256:6b53d4cc5c013b08157471d11f7a7c2c45f9e8238f3958e3b2f04ec1773ecbd4"
RULES = {
    "100101": ("AUTH-JSON", "synthetic", "Baixa", "Falha de autenticação em fixture"),
    "100102": ("AUTH-JSON", "synthetic", "Alta", "Correlação de fixtures por IP e execução"),
    "100103": ("PROC-001", "synthetic", "Média", "Opção de codificação em fixture PowerShell"),
    "100105": ("FIM-001", "controlled_live_fim", "Baixa", "Arquivo modificado no endpoint"),
    "100110": ("AUTH-SSH", "controlled_live_ssh", "Baixa", "Falha de senha SSH no endpoint"),
    "100111": ("AUTH-SSH", "controlled_live_ssh", "Alta", "Falhas SSH correlacionadas por IP"),
    "100112": ("AUTH-SSH", "controlled_live_ssh", "Informativa", "Login SSH autorizado"),
    "100113": ("FIM-001", "controlled_live_fim", "Baixa", "Arquivo criado no endpoint"),
    "100114": ("FIM-001", "controlled_live_fim", "Baixa", "Arquivo excluído no endpoint"),
}


def compose(*args, input_text=None, check=True, timeout=90):
    return subprocess.run(
        ["docker", "compose", "--project-name", "soc-homelab", *args],
        cwd=ROOT, input=input_text, text=True, encoding="utf-8",
        capture_output=True, check=check, timeout=timeout,
    )


def utc_timestamp(value):
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError("Evidence timestamp must include a UTC offset")
    return stamp


def json_lines(text):
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"Expected a JSON object on line {number}")
        rows.append(row)
    return rows


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

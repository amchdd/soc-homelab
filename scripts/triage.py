"""Build a static, portable evidence report; never infer a confirmed incident."""
import argparse
import hashlib
import html
import json
from collections import Counter
from pathlib import Path
from common import RULES, VERSION, json_lines
from export_evidence import require_coverage


def priority(rule_id):
    return RULES[str(rule_id)][2]


def summarize(path):
    alerts = [row for row in json_lines(Path(path).read_text(encoding="utf-8"))
              if str(row.get("rule", {}).get("id")) in RULES]
    return alerts, Counter(str(row["rule"]["id"]) for row in alerts)


def render_report(alerts, manifest, tests):
    require_coverage(alerts)
    counts = Counter(str(row["rule"]["id"]) for row in alerts)
    lines = [
        "# Relatório de validação — SOC Home Lab", "",
        f"Versão de portfólio: {VERSION} · Wazuh {manifest['engine_version']}",
        f"Execução: {manifest['run_id']} · {manifest['started_at']} a {manifest['completed_at']}", "",
        "## Resultado", "",
        f"- {sum(test['passed'] for test in tests)}/{len(tests)} casos de regressão no motor Wazuh.",
        f"- {len(alerts)} alertas exportados; cobertura das {len(RULES)} regras previstas.",
        "- Autenticação SSH e FIM produzidos por operações controladas em um endpoint Linux com agente.",
        "- Fixtures JSON identificadas como sintéticas; nenhum comando PowerShell foi executado.",
        "- Decisão de triagem: encerrar como exercício autorizado. Não há afirmação de incidente ou comprometimento.", "",
        "## Cobertura", "",
        "| Regra | Cenário | Origem | Alertas | Prioridade no exercício |",
        "|---|---|---|---:|---|",
    ]
    for rule_id, (scenario, origin, operational_priority, _) in RULES.items():
        lines.append(f"| {rule_id} | {scenario} | {origin} | {counts[rule_id]} | {operational_priority} |")
    lines += [
        "", "## Análise de triagem", "",
        "**AUTH-SSH:** houve uma sequência de senhas deliberadamente incorretas para a conta de laboratório, seguida de login com a credencial temporária autorizada. O serviço OpenSSH gerou os logs; o agente os enviou ao manager, que aplicou a correlação. A origem é loopback do contêiner, não um atacante externo. O sucesso posterior é contexto para investigação, não prova de abuso.", "",
        "**FIM-001:** criação, modificação e exclusão foram executadas em arquivos exclusivos desta execução. Os hashes exportados foram comparados com os valores esperados antes da aprovação. As mudanças são autorizadas; nenhuma técnica ATT&CK é atribuída apenas por uma mudança de arquivo.", "",
        "**AUTH-JSON e PROC-001:** os testes demonstram decodificação e regras sobre fixtures, com controles de aplicações, origens, IPs, execuções e opções semelhantes. A linha PowerShell é somente um dado do exercício. Não há endpoint Windows ou telemetria Sysmon nesta versão.", "",
        "**Escalonamento em um ambiente operacional:** buscar conta/origem inesperada, contexto de mudança, processo pai e evidências adicionais. Nível da regra e codificação de comando, isoladamente, não confirmam incidente.", "",
        "## Linha do tempo dos alertas", "",
    ]
    for alert in alerts:
        rule_id = str(alert["rule"]["id"])
        description = str(alert["rule"]["description"]).replace("\n", " ")
        lines.append(f"- {alert['timestamp']} · {alert['agent']['name']} · {rule_id} · {description}")
    return "\n".join(lines) + "\n"


def render_html(alerts, manifest, tests):
    esc = html.escape
    counts = Counter(str(row["rule"]["id"]) for row in alerts)
    live = sum(row["origin"] != "synthetic" for row in alerts)
    rows = "".join(
        f"<tr><td><code>{key}</code></td><td>{esc(value[3])}</td>"
        f"<td>{esc(value[1])}</td><td>{counts[key]}</td><td>{esc(value[2])}</td></tr>"
        for key, value in RULES.items()
    )
    timeline = "".join(
        f"<li><time>{esc(row['timestamp'])}</time><br><code>{esc(row['agent']['name'])} · "
        f"{esc(str(row['rule']['id']))}</code> {esc(str(row['rule']['description']))}</li>"
        for row in alerts
    )
    controls = "".join(
        f"<li>{'PASS' if case['passed'] else 'FAIL'} — {esc(case['case'])}</li>" for case in tests
    )
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Home Lab — Relatório de validação</title>
<style>
:root{{color-scheme:light dark;--bg:#f5f7fa;--surface:#fff;--text:#18232e;--muted:#536373;--line:#d9e0e7;--accent:#075c68}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d141c;--surface:#16212d;--text:#edf3f8;--muted:#adbac7;--line:#334457;--accent:#69c6d0}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.65 system-ui,sans-serif}}
main{{max-width:1040px;margin:auto;padding:48px 24px}}header{{border-bottom:2px solid var(--accent);padding-bottom:24px}}
h1{{font-size:clamp(28px,4vw,44px);line-height:1.2;margin:8px 0 16px}}h2{{font-size:24px;margin-top:40px}}
.small,time{{color:var(--muted);font-size:14px}}.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:28px 0}}
.stat{{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:20px}}.stat strong{{font-size:32px;display:block;color:var(--accent)}}
.notice{{padding:18px 20px;background:var(--surface);border-left:4px solid var(--accent)}}.table{{overflow-x:auto}}
table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{text-align:left;padding:12px;border-bottom:1px solid var(--line)}}
td{{vertical-align:top}}code{{font:13px ui-monospace,monospace;overflow-wrap:anywhere}}li{{margin-bottom:12px}}a{{color:var(--accent)}}
@media(max-width:600px){{main{{padding:24px 16px}}.stats{{grid-template-columns:1fr;gap:8px}}.stat{{padding:12px 16px}}.stat strong{{font-size:26px}}}}
@media print{{body{{background:white;color:#111}}main{{padding:0}}.stat{{break-inside:avoid}}}}
</style></head><body><main>
<header><div class="small">PORTFÓLIO · VERSÃO {VERSION} · WAZUH {esc(manifest['engine_version'])}</div>
<h1>SOC Home Lab</h1><p>Autenticação Linux, integridade de arquivos e triagem com evidências verificáveis.</p>
<div class="small">Execução {esc(manifest['run_id'])}<br>{esc(manifest['started_at'])} a {esc(manifest['completed_at'])}</div></header>
<div class="stats"><div class="stat"><strong>{sum(case['passed'] for case in tests)}/{len(tests)}</strong>casos no motor</div>
<div class="stat"><strong>{len(RULES)}/{len(RULES)}</strong>regras com evidência</div>
<div class="stat"><strong>{live}</strong>alertas de operações reais controladas</div></div>
<p class="notice"><strong>Resultado: exercício autorizado.</strong> OpenSSH e FIM geraram telemetria real no contêiner Linux.
As fixtures JSON permanecem identificadas como simulações. Não há alegação de incidente ou comprometimento.</p>
<h2>Arquitetura validada</h2><p>OpenSSH / arquivos do endpoint → agente Wazuh → manager → regras locais → exportação filtrada → triagem.
O ambiente não publica portas no host; SSH escuta somente no loopback do endpoint.</p>
<h2>Cobertura de detecção</h2><div class="table"><table><thead><tr><th>Regra</th><th>Sinal</th><th>Origem</th><th>Alertas</th><th>Prioridade</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Conclusões de triagem</h2><p><strong>SSH:</strong> senhas incorretas controladas, correlação por origem e login autorizado posterior.
A origem é 127.0.0.1 no contêiner. O login bem-sucedido é contexto; não comprova acesso indevido.</p>
<p><strong>FIM:</strong> criação, alteração e exclusão de arquivos exclusivos da execução, com comparação dos hashes.
Decisão: mudança autorizada; sem contenção ou atribuição arbitrária de técnica ATT&amp;CK.</p>
<p><strong>PowerShell:</strong> fixture de texto com opção de codificação, validada com controles negativos. O comando não foi executado; não existe coleta de Windows/Sysmon nesta versão.</p>
<h2>Regressão no motor</h2><ul>{controls}</ul>
<h2>Linha do tempo</h2><ol>{timeline}</ol>
<h2>Integridade e escopo</h2><p>O manifesto registra versões, imagens e SHA-256 dos arquivos de evidência. Hashes verificam integridade dos arquivos;
não são assinatura digital ou comprovação independente de autoria. Esta versão de portfólio é um estudo isolado, sem indexer/dashboard,
contenção automática ou compromisso de manutenção contínua.</p>
<p class="small">Artefatos desta pasta: <a href="alerts.jsonl">alertas</a> · <a href="rule-tests.json">regressão</a> · <a href="manifest.json">manifesto</a> · <a href="triage.md">triagem em Markdown</a>.</p>
</main></body></html>"""


def verify_hashes(folder, hashes):
    folder = Path(folder)
    for name, expected in hashes.items():
        path = (folder / name).resolve()
        if not path.is_relative_to(folder.resolve()):
            raise ValueError("Artifact path leaves evidence folder")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Artifact hash mismatch: {name}")
def verify_manifest(folder, verify_source=False):
    folder = Path(folder)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "passed":
        raise ValueError("Snapshot is not marked as verified")
    required = {"alerts.jsonl", "rule-tests.json", "triage.md", "report.html", "ssh-auth.log", "fim-changes.json"}
    if set(manifest.get("artifacts_sha256", {})) != required:
        raise ValueError("Snapshot artifact set is incomplete or unexpected")
    verify_hashes(folder, manifest["artifacts_sha256"])
    alerts, _ = summarize(folder / "alerts.jsonl")
    require_coverage(alerts)
    tests = json.loads((folder / "rule-tests.json").read_text(encoding="utf-8"))["results"]
    if not tests or not all(case.get("passed") is True for case in tests):
        raise ValueError("Snapshot contains failing or absent engine tests")
    if manifest.get("alert_count") != len(alerts) or manifest.get("rule_test_count") != len(tests):
        raise ValueError("Snapshot counts disagree with evidence")
    if verify_source:
        from common import ROOT
        hashes = manifest.get("configuration_sha256", {})
        if not hashes:
            raise ValueError("Snapshot contains no source hashes")
        verify_hashes(ROOT, hashes)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?")
    parser.add_argument("--output", default="runtime/triage.md")
    parser.add_argument("--verify", metavar="FOLDER")
    parser.add_argument("--verify-source", action="store_true")
    args = parser.parse_args()
    if args.verify:
        manifest = verify_manifest(args.verify, args.verify_source)
        print(f"Snapshot integrity verified: {manifest['run_id']}")
        return
    if not args.input:
        parser.error("input or --verify is required")
    folder = Path(args.input).parent
    alerts, _ = summarize(args.input)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    tests = json.loads((folder / "rule-tests.json").read_text(encoding="utf-8"))["results"]
    Path(args.output).write_text(render_report(alerts, manifest, tests), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()

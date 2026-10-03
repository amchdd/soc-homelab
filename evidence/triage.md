# Relatório de validação — SOC Home Lab

Versão de portfólio: 1.0.0 · Wazuh 4.14.8
Execução: bca2a1b54d3b4828babaab1ea9208424 · 2026-09-28T23:48:12.704694+00:00 a 2026-09-28T23:49:46.583959+00:00

## Resultado

- 18/18 casos de regressão no motor Wazuh.
- 21 alertas exportados; cobertura das 9 regras previstas.
- Autenticação SSH e FIM produzidos por operações controladas em um endpoint Linux com agente.
- Fixtures JSON identificadas como sintéticas; nenhum comando PowerShell foi executado.
- Decisão de triagem: encerrar como exercício autorizado. Não há afirmação de incidente ou comprometimento.

## Cobertura

| Regra | Cenário | Origem | Alertas | Prioridade no exercício |
|---|---|---|---:|---|
| 100101 | AUTH-JSON | synthetic | 7 | Baixa |
| 100102 | AUTH-JSON | synthetic | 1 | Alta |
| 100103 | PROC-001 | synthetic | 1 | Média |
| 100105 | FIM-001 | controlled_live_fim | 1 | Baixa |
| 100110 | AUTH-SSH | controlled_live_ssh | 7 | Baixa |
| 100111 | AUTH-SSH | controlled_live_ssh | 1 | Alta |
| 100112 | AUTH-SSH | controlled_live_ssh | 1 | Informativa |
| 100113 | FIM-001 | controlled_live_fim | 1 | Baixa |
| 100114 | FIM-001 | controlled_live_fim | 1 | Baixa |

## Análise de triagem

**AUTH-SSH:** houve uma sequência de senhas deliberadamente incorretas para a conta de laboratório, seguida de login com a credencial temporária autorizada. O serviço OpenSSH gerou os logs; o agente os enviou ao manager, que aplicou a correlação. A origem é loopback do contêiner, não um atacante externo. O sucesso posterior é contexto para investigação, não prova de abuso.

**FIM-001:** criação, modificação e exclusão foram executadas em arquivos exclusivos desta execução. Os hashes exportados foram comparados com os valores esperados antes da aprovação. As mudanças são autorizadas; nenhuma técnica ATT&CK é atribuída apenas por uma mudança de arquivo.

**AUTH-JSON e PROC-001:** os testes demonstram decodificação e regras sobre fixtures, com controles de aplicações, origens, IPs, execuções e opções semelhantes. A linha PowerShell é somente um dado do exercício. Não há endpoint Windows ou telemetria Sysmon nesta versão.

**Escalonamento em um ambiente operacional:** buscar conta/origem inesperada, contexto de mudança, processo pai e evidências adicionais. Nível da regra e codificação de comando, isoladamente, não confirmam incidente.

## Linha do tempo dos alertas

- 2026-09-28T23:49:37.153+0000 · soc-manager · 100101 · SOC lab authentication fixture for labuser
- 2026-09-28T23:49:37.154+0000 · soc-manager · 100101 · SOC lab authentication fixture for labuser
- 2026-09-28T23:49:37.154+0000 · soc-manager · 100101 · SOC lab authentication fixture for labuser
- 2026-09-28T23:49:37.154+0000 · soc-manager · 100101 · SOC lab authentication fixture for labuser
- 2026-09-28T23:49:37.156+0000 · soc-manager · 100101 · SOC lab authentication fixture for labuser
- 2026-09-28T23:49:37.156+0000 · soc-manager · 100101 · SOC lab authentication fixture for labuser
- 2026-09-28T23:49:37.157+0000 · soc-manager · 100101 · SOC lab authentication fixture for labuser
- 2026-09-28T23:49:37.160+0000 · soc-manager · 100102 · SOC lab repeated authentication fixtures from 192.0.2.10
- 2026-09-28T23:49:37.160+0000 · soc-manager · 100103 · SOC lab encoded PowerShell fixture requires contextual review
- 2026-09-28T23:49:41.133+0000 · soc-endpoint · 100110 · SOC lab SSH password authentication failed for labuser
- 2026-09-28T23:49:41.180+0000 · soc-endpoint · 100110 · SOC lab SSH password authentication failed for labuser
- 2026-09-28T23:49:41.180+0000 · soc-endpoint · 100110 · SOC lab SSH password authentication failed for labuser
- 2026-09-28T23:49:43.134+0000 · soc-endpoint · 100110 · SOC lab SSH password authentication failed for labuser
- 2026-09-28T23:49:43.140+0000 · soc-endpoint · 100111 · SOC lab repeated SSH password failures from 127.0.0.1
- 2026-09-28T23:49:43.146+0000 · soc-endpoint · 100110 · SOC lab SSH password authentication failed for labuser
- 2026-09-28T23:49:45.133+0000 · soc-endpoint · 100110 · SOC lab SSH password authentication failed for labuser
- 2026-09-28T23:49:45.140+0000 · soc-endpoint · 100110 · SOC lab SSH password authentication failed for labuser
- 2026-09-28T23:49:45.146+0000 · soc-endpoint · 100112 · SOC lab successful SSH authentication (context only)
- 2026-09-28T23:49:46.028+0000 · soc-endpoint · 100105 · SOC lab endpoint FIM: file modified
- 2026-09-28T23:49:46.041+0000 · soc-endpoint · 100113 · SOC lab endpoint FIM: file created
- 2026-09-28T23:49:46.084+0000 · soc-endpoint · 100114 · SOC lab endpoint FIM: file deleted

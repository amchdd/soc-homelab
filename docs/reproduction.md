# Reprodução e diagnóstico

## Pré-requisitos

- Contêineres Linux amd64 e Docker com Compose v2.
- Python 3.10+; as ferramentas usam apenas a biblioteca padrão.
- Espaço para imagens, volumes e evidências; limites de memória constam em compose.yaml.
- Acesso ao Docker Hub e ao repositório fixado do Amazon Linux durante o primeiro build.

Não é necessário Docker para ler o relatório ou verificar os artefatos já publicados.

## Execução

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/triage.py --verify evidence --verify-source
python3 scripts/run_lab.py
```

Os resultados novos ficam em `runtime/runs/<run_id>/`. Abra `report.html` desse diretório ou consulte `triage.md`.

Para inspecionar o ambiente antes da parada:

```bash
python3 scripts/run_lab.py --keep-running
docker compose ps
docker compose exec -T manager /var/ossec/bin/agent_control -l
docker compose exec -T endpoint cat /var/log/lab-auth.log
docker compose logs --tail=50 manager endpoint
docker compose stop
```

## Windows

Com Docker Desktop funcional, as ferramentas também podem ser chamadas pelo Python no terminal. Se usar Docker Engine dentro do WSL2, execute o projeto dentro da distribuição com permissão no socket do Docker e mantenha uma sessão WSL aberta.

Exemplo dentro do WSL2:

```bash
cd /mnt/c/caminho/para/soc-homelab
python3 scripts/run_lab.py
```

Os arquivos usam UTF-8; o Git normaliza os finais de linha para LF. Isso evita problemas com scripts do contêiner e diferenças de hash por finais de linha.

## Falhas comuns

| Sinal | Verificação |
|---|---|
| Docker indisponível / permissão no socket | Confirmar Engine, distribuição WSL e acesso ao Docker |
| Endpoint não fica ativo | Conferir saúde do manager, logs do endpoint e cadastro pelo agent_control |
| Erros de fork/thread | Conferir limite de tarefas e recursos; não aprovar um serviço parcialmente iniciado |
| FIM sem baseline | Conferir agente e montagem da pasta runtime/protected |
| Regra de controle falhando | Consultar rule-tests.json da execução, com a saída real do motor |
| Cobertura incompleta | Ler failure.json; não reaproveitar alertas de execução anterior |
| Hash divergente | Conferir versão do checkout, mudanças locais e eventos FIM observados |
| Build indisponível | Conferir disponibilidade do registro e do repositório fixado |

O runner tem prazos de espera e termina com erro quando faltam evidências. Uma execução interrompida não substitui o snapshot validado.

## Encerramento e reprodução estática

`docker compose stop` preserva volumes. `docker compose down` remove os contêineres e a rede, mantendo os volumes. O relatório e os arquivos já exportados continuam disponíveis sem serviços em execução.

A versão de portfólio não requer uma rotina de atualização. Para reaproveitar o ambiente em outro contexto, crie uma versão própria, revise as dependências e repita a validação; não trate o snapshot como configuração de produção.

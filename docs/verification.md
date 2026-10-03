# Verificação da versão de portfólio

O snapshot publicado em [evidence/](../evidence/) resulta de uma execução completa do Wazuh **4.14.8**, com manager e endpoint Linux em contêineres. O [manifesto](../evidence/manifest.json) registra os horários e a identificação exata da execução.

## Critérios de aprovação

- **18/18 casos** no motor: regras positivas, controles negativos e correlação.
- **12/12 testes Python**: evidência antiga, execução diferente, origem/ativo incorretos, duplicação, JSON inválido, hashes, cobertura incompleta e escape do relatório HTML.
- Endpoint cadastrado e ativo no manager, com baseline FIM concluída antes das operações.
- Oito falhas de senha e um login autorizado confirmados nos logs nativos do OpenSSH.
- Cobertura das nove regras de ponta a ponta nesta execução.
- Criação, alteração e exclusão FIM com hashes esperados conferidos.
- Artefatos completos e hashes de evidência e dos arquivos de configuração/código.
- Rejeição de alterações no código durante a própria execução.
- Parada dos contêineres ao final do runner, salvo opção explícita de inspeção.

Os números de alertas e timestamps devem ser consultados no manifesto e no relatório; podem variar entre execuções. A referência é cobertura e validade, não uma contagem fixa de alertas.

## Conferir sem iniciar Docker

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/triage.py --verify evidence --verify-source
```

A segunda chamada verifica hashes dos artefatos, cobertura de regras, resultados e contagens. Com `--verify-source`, também compara os hashes com os arquivos deste checkout. Isso deve ser feito na mesma versão usada para produzir o snapshot.

Os hashes não são uma assinatura digital; alguém que altere arquivos e o próprio manifesto pode gerar novos hashes. O manifesto serve para detectar alterações em relação ao registro publicado.

## Reproduzir a validação do motor

```bash
python3 scripts/run_lab.py
```

A saída fica em `runtime/runs/<run_id>/`. O snapshot publicado não é substituído por essa chamada. Para produzir deliberadamente outra referência, use `--snapshot` depois de revisar o escopo da mudança.

A CI verifica o snapshot publicado, as ferramentas e uma nova execução do ambiente. Ela não atualiza os arquivos de evidência do repositório.

## Origem dos resultados

| Resultado | Origem |
|---|---|
| Logs SSH | Serviço OpenSSH e operações locais controladas |
| Alertas SSH | Coleta pelo agente, transporte ao manager e análise de regras |
| FIM | Criação, modificação e exclusão reais em arquivos exclusivos |
| Autenticação JSON e PowerShell | Fixtures explicitamente sintéticas |
| Regressão | Saída real de sessões separadas do wazuh-logtest |

No FIM de exclusão, `sha256_after` representa o último hash conhecido, acompanhado de `event=deleted`. Esse comportamento foi observado na execução e é tratado explicitamente pelo validador.

O relatório fecha os cenários como exercícios autorizados. Não há afirmação de incidente real, contenção de atacante, experiência profissional em SOC ou execução de Windows/Sysmon.

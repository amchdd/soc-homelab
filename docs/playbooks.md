# Playbooks de triagem N1

Escopo: contêineres exclusivos do laboratório. A prioridade abaixo é uma decisão operacional do exercício; não equivale ao nível numérico do Wazuh. Nenhuma contenção é executada automaticamente.

## AUTH-SSH — autenticação Linux

**Sinais:** 100110 (falha), 100111 (correlação) e 100112 (sucesso autorizado). Telemetria produzida pelo OpenSSH e coletada pelo agente `soc-endpoint`.

1. Preservar horário, agente, origem, conta, serviço, regra e logs de origem. Correlacionar `ssh-auth.log` com os alertas.
2. Confirmar a sequência: oito senhas deliberadamente incorretas, origem loopback `127.0.0.1` e um login com credencial temporária válida.
3. Distinguir falha de senha, correlação de tentativas e sucesso de autenticação. Um sucesso posterior aumenta a necessidade de contexto, mas não comprova acesso indevido.
4. Considerar senha desatualizada, tarefa automática, erro de usuário e teste autorizado. Em produção, buscar outras contas, origem externa e atividade após o login.
5. Escalar se houver conta privilegiada, origem inesperada, recorrência sem explicação ou uso indevido corroborado. O teste local não fornece histórico operacional ou reputação de IP.

**Prioridade do exercício:** alta para a sequência correlacionada; informativa para o sucesso isolado.

**Decisão registrada:** exercício autorizado. O login executa apenas a confirmação do cenário. A conta recebe senha temporária e é bloqueada pelo runner depois do teste; esse bloqueio encerra o exercício e não é uma resposta automática a incidente.

**MITRE:** T1110 descreve a hipótese de tentativas repetidas. A execução controlada não comprova um ataque externo nem uma conta comprometida.

## AUTH-JSON — correlação de fixtures

**Sinais:** 100101 e 100102. A origem é `synthetic`; o alerta e o processamento pelo manager são reais.

1. Verificar `lab`, `origin`, `run_id`, `event_id`, usuário e IP reservado de documentação.
2. Conferir que os eventos pertencem à mesma execução e origem.
3. Comparar os controles de IPs diferentes e execuções diferentes: não devem disparar a correlação.
4. Usar o resultado do motor para verificar o limiar; não inferir comportamento apenas pelo nome da regra.
5. Não usar timestamps contidos na fixture como prova de atividade de um endpoint real. A janela demonstrada usa o tempo de processamento do manager.

**Decisão:** validar a regra e encerrar como simulação autorizada.

## PROC-001 — PowerShell com codificação

**Sinal:** 100103, sobre fixture JSON de criação de processo. Não há execução de PowerShell ou coleta Sysmon.

1. Preservar o comando como dado, com processo, origem, identificação do evento e resultado da regra.
2. Comparar PowerShell/pwsh, a forma abreviada `-enc`, opções semelhantes e o controle `Get-Date`.
3. Decodificar o Base64 apenas como texto. A fixture gerada contém uma mensagem benigna; não executar o conteúdo.
4. Para investigação operacional, obter processo pai, assinatura do executável, contexto de automação e telemetria de rede. Estes dados não existem nesta fixture.
5. Escalar apenas com contexto suspeito ou evidências adicionais. A opção de codificação isolada não comprova malware.

**Prioridade:** média, para validar contexto. **Decisão:** fixture autorizada. T1059.001 é uma referência técnica do cenário, não uma atribuição de comprometimento.

A detecção procura as opções `-enc` e `-EncodedCommand`, sem diferenciar maiúsculas/minúsculas. Não é um parser completo da linha de comando nem cobre todas as abreviações possíveis.

## FIM-001 — integridade do endpoint

**Sinais:** 100105 (modificado), 100113 (adicionado) e 100114 (excluído). Todos vêm do FIM nativo do agente.

1. Confirmar ativo, caminho exclusivo da execução, `event`, modo de detecção e horário.
2. Comparar com `fim-changes.json`: hash anterior/atual para alteração, hash do novo arquivo e último hash conhecido do arquivo excluído.
3. Em Wazuh 4.14.8, uma exclusão usa `sha256_after` para o último registro conhecido. O arquivo não existe após a operação.
4. Confirmar a mudança autorizada do exercício e verificar que o exportador rejeita hashes incompatíveis.
5. Em produção, consultar autorização e investigar alterações sem ticket, caminhos críticos ou outros sinais de comprometimento.

**Prioridade:** baixa neste exercício autorizado. **Decisão:** validar FIM e encerrar. Nenhuma técnica ATT&CK é atribuída somente por haver mudança.

O modo observado pode ser `realtime` ou `scheduled`, conforme o sistema de arquivos do host. Os resultados preservam o valor observado, sem inventar o modo.

## Registro de investigação

| Campo | Conteúdo esperado |
|---|---|
| Identificação | Execução, data/hora, cenário e responsável pela revisão |
| Telemetria | Fonte, agente e distinção entre operação controlada e fixture |
| Evidências | Eventos, alertas, caminhos, hashes e sequência temporal |
| Hipóteses | Explicação provável e alternativas operacionais |
| Lacunas | Dados que não foram coletados ou não podem ser concluídos |
| Prioridade | Justificativa separada do nível da regra |
| Decisão | Observar, escalar ou encerrar; ações realmente realizadas |

O relatório automático organiza evidências. A aplicação destes critérios em uma investigação operacional depende de análise humana e contexto.

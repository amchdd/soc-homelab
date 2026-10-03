# Decisões de projeto

## Perfil de portfólio fechado

O projeto demonstra a cadeia de coleta, detecção, evidência e triagem para um conjunto limitado de cenários. O relatório estático pode ser consultado sem iniciar o ambiente. Não há roadmap de novas funcionalidades nem atualização periódica do snapshot.

A versão fixa Wazuh 4.14.8 por digest, repositório Amazon Linux `2023.12.20260831` e versões dos pacotes OpenSSH/rsyslog. A CI usa ações fixadas por commit e não tem agendamento. O sistema ainda depende da disponibilidade desses serviços para um novo build; o relatório publicado não depende deles.

## Endpoint separado

O agente está no contêiner `soc-endpoint`, enquanto análise e fixtures JSON ficam no manager. Isso permite verificar coleta no endpoint e transporte ao manager. O contêiner é um endpoint Linux de exercício, não monitora o sistema Windows ou todos os processos do host.

O SSH escuta em loopback e usa a mesma conta exclusiva durante o teste. A origem real é `127.0.0.1`; não se transforma esse dado em um IP externo fictício. A senha é gerada por execução, transmitida pelo stdin e descartada. O runner bloqueia a conta ao terminar a autenticação.

## Recursos e isolamento

A rede Docker é interna, sem portas publicadas. Não há Docker socket, modo privilegiado ou diretórios pessoais montados. O agente lê somente a pasta de arquivos do exercício e seus logs de autenticação.

Os limites são 2 GiB/1024 tarefas para o manager e 768 MiB/256 tarefas para o endpoint. As threads do Wazuh contam como tarefas; um limite excessivamente baixo pode impedir o logcollector de iniciar. A checagem de saúde do manager exige analysisd e logcollector.

FIM ocorre no endpoint. Inventário, SCA, vulnerabilidades, indexer, dashboard e resposta automática estão fora do perfil. O Filebeat fica ocioso, pois não há indexer.

## Regras e controles

- Os IDs locais ficam no intervalo 100100–100114.
- As fixtures exigem os marcadores do laboratório e `origin=synthetic`.
- A correlação JSON exige mesmo IP e mesma execução.
- As regras SSH locais são restritas à conta `labuser`; não são uma política geral de proteção de SSH.
- O login autorizado é um sinal de contexto, não uma detecção de abuso.
- A política padrão de horário comercial `0215-policy_rules.xml` foi excluída: este laboratório não possui jornada operacional definida. Isso evita resultados dependentes do horário de execução.
- FIM exige caminhos desta execução e hashes compatíveis; não há inferência arbitrária de técnica ATT&CK.

## Evidências e limites

Cada execução recebe identificação própria. O exportador filtra por horário, origem, regra, agente e marcadores, deduplica alertas e exige cobertura completa. A publicação só ocorre depois da validação; arquivos de execução ficam separados do snapshot de referência.

As fontes e configurações são verificadas por hash no início e no fim. O relatório HTML escapa dados antes de renderizar e usa apenas HTML/CSS, sem JavaScript, fontes ou serviços externos.

O laboratório não mede desempenho de produção, retenção, escalabilidade, coleta tardia ou investigação multihost. Os casos de PowerShell são fixtures; faltam processo pai, assinatura e telemetria Windows. Esses limites fazem parte da versão, não uma lista de funcionalidades prometidas.

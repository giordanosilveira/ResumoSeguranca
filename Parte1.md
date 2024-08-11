# 1. Vulnerabilidades em redes
Resumo para a parte um da matéria de segunraça computacional.

## 1.1 Terminologias
Qual a diferença entre bug, falha e vulnerabilidade ?

- Bug: Erro presente em um código de um software, que pode não ser encontrado.
- Falha: Problema de software em nível mais profundo do que um bug. É instanciada no código, mas pode existir no projeto.
- Vulnerabilidades: Falha ou um bug que pode ser explorado por atacantes.

## 1.2 Princípios básicos
Segunrança computacional reside em:
- Confidencialidade: Segredo, ocultação, encobrimento de informações ou recursos.
  - Mecanismos de suporte: controle de acesso.
  - Implementação do mecanismo de suporte: Criptografia.
- Integridade: Confiança nos dados ou recurso: Relacionada à prevenção de mudanças impróprias ou não-autorizadas. A integridade nos dados, tanto na origem dos dados.
  - Mecanismos de suporte: prevenção e/ou detecção.
    - Prevenção: Mantêm a integridade pelo bloqueio de qualquer tentativa não-autorizada de modificação dos dados ou tentativas de modificar o dado de maneira não autorizada.
    - Detecção: Alertam que a integridade dos dados não foi preservada.
- Disponibilidade: Habilidade de se usar a informação ou recurso desejado. Um sistema indisponível é tão ruim quanto um sistema inexistente.
    - Tentaticas de bloquear a disponibilidade são difíceis de se detectar: o padrão de acesso incomum é uma anomalia momentânea, uma falha de dispositivo/recurso ou um ataque proposital ?


## 1.3 Gerenciamento de Vulnerabilidades vs. Análise de Risco
| Gerenciamento de Vulnerabilidades | Análise de Risco |
| --- | --- |
| O foco é nas consequências para o “objeto” e nas consequências primárias e secundárias para o ambiente associado ao objeto em questão | O objetivo é investiga os rescos associados a algum "objeto", seu projeto e operações|
| Lida com as possibilidades de redução de tais consequências e de melhoria na capacidade de gerenciar incidentes futuros | O foco é nas causas e consequências diretas para o objeto em questão |
| Exemplo: Servidor de documentos interno mal configurado permite acesso externo não autenticado devido a falta de atualização do SO/Aplicação | Exemplo: Risco -> vazamento de informações sensíveis. Possível causa -> não implementação de políticas de confidencialidade por explosição. Consequência direta -> perda de confidencialidade por exposição. |


## 1.4 Classes de ameaças:
Um ataque pode ser uma (ou mais) das seguintes classes:

- Dissminação/Exposição: Acesso não autorizado a informação.
- Enganação: Aceitação de dados falsos ou forjados.
- Disrupção: Interrupção da operação "normal".
- Ususrpação: Controle não autorizado de um sistema.

### 1.4.1 Espionagem
Interceptação da informção.
- Classe de ameaças: **Exposição** não autorizada de dados sensíveis.
- Tipo de ataque: **Passívo**. Escuta/leitura/acesso a comunicações/arquivos/informações.
- Viola: **confidencialidade**

### 1.4.2 Modificação
Mudança (não autorizada) da informação.
- Classe de ameaças: **Enganação**, porém leva a **Disrupção** e a **Usurpação**, pois dados podificados podem controlar operações no sistema atacado. A confiança em dados incorretos induz as ações posteriores.
- Tipo de ataque: **Ativo**. Resulta em mudanças na informação.
- Viola: **Integridade**.

### 1.4.3 Mascaramento:
Personificação da "identidade".
- Classes de ameaças: **Enganação** e **Usurpação**. Faz com que uma ponta da comunicação acredite que a outra ponta é uma entidade diferente.
- Tipo de ataque: **Passívo** ou **Ativo**.
  - Passívo: A vítima meramente acessa a entidade forjada.
  - Ativo: O atacante engana o usuário quanto a sua identidade.
- Viola: **Integridade**.

### 1.4.4 Repúdio da origem:
É uma falsa negativa de que uma entidade **enviou/criou** algum objeto ou dado.
- Classe de ameaças: **Enganação**.
- Tipo de ataque: **Ativo**.
- Viola: **Integridade**.


### 1.4.5 Negativa de recebimento:
É uma falsa negativa de que uma entidade **recebeu** algum objeto/dado.
- Classe de ameaças: **Enganação**.
- Tipo de ataque: **Ativo**.
- Viola: **Integridade** e **Disponibilidade**.


### 1.4.6 Atraso:
Inibição **temporária** de um serviço.
- Classe de ameaças: **Usurpação**, mas pode auxiliar na **Enganação**. Se um atacante manipula estruturas de controle de um sistema ou rede, pode forçar a demora na entrega de um dado. QUando uma entidade espera por uma autorização atrasada, o atacante pode "mascarar" um servidor secundário que provê informações incorretas.
- Tipo de ataque: **Ativo**.
- Viola: **Disponibilidade**.


### 1.4.7 DoS:
Inibição de um serviço a longo prazo.
- Classe de ameaças: **Usurpação**, mas pode auxiliar na **Enganação**. Impede um servidor de obter recursos (DoS na origem), ou atender requisições de clientes (DoS no destino), ou descarta mensagem de um ou ambos os lados da comunicação (DoS no caminho intermediário). Origem do ataque é geralmente forjada. O atacante pode bloquear o servidor legítimo e desviar o tráfego dos clientes para servidores comprometidos.
- Tipo de ataque: **Ativo**.
- Viola: **Disponibilidade**.

## 1.5 Passos de um ataque:
Um ataque consiste de um conjunto de etapas para ter sucesso:
1. Reconhecimento e enumeração: Levantamentos de dados do alvo, publicamente disponíveis, isto é, estrutura do alvo, informações de funcionários, IP, portas abertas. Dividídas em **varredura** e **enumeração**.
    - Varredura: Processo para identificar recursos "acessíveis" na rede ou sistema alvo. 
    - Enumeração: Obtenção de detalhes sobre os recursos online identificados.
2. Ganho de acesso (intrusão): Dividida em **compromentimento inicial** e **escalada**.
    - Compromentimento inicial: Algum nível de acesso é alcançado.
    - Escalada: Ganho de privilégios adicionais.
3. Manutenção do controle (persistência): Eliminação da vulneravilidade explorada na intrasão. Preparo do "retorno" (um exemplo é o backdoor).
4. Ocultação de traços (limpeza): Listagem das atividades realizadas e artefatos gerados para remoção de evidências.
5. [Fazer o alvo trabalhar para o atacante.]

### 1.5.1 nmap 

## 1.6 Atividades subversivas:
Programas maliciosos podem fazer as seguinttes atividades subversivas/suspeitas:
1. Coleta de dados:
    - Captura de pacotes (*sniffing*)
    - Captura de pressionamente de teclas:
        - keyloggers.
    - Escoamento de banco de dados.
2. Ocultação de presença:
    - Ocultação de arquivos.
    - Ocultação de processos.
        - _rootkits_: esconder o processo malicioso da lista de processos do sistema.
    - Ocultação de usuários.
3. Comunicação dissimulada
    - Permite **acesso** remoto sem detecção por parte da vítima.
    - Trasferência de dados sensíveis para fora do sistema da vítima.
    - Cannais dissimulados e esteganografia: Uso de campos vazios em protocoloes de aplicação legítimos; informações embutidas em figuras.
4. Comando e controle.
    - Permite **controle** remoto de um sistema.
    - Sabotagem: instalação de um _Trojan_ que modifique a execução de um programa legítimo.
    - DoS







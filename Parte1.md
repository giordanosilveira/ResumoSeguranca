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
O Nmap (Network Mapper) é uma ferramenta poderosa e versátil para a exploração de redes e auditorias de segurança. Aqui estão alguns possíveis tipos de scan no Nmap:
1. -sT, TCP Connect Scan: Este é o scan mais básico e confiável do Nmap. Ele estabelece uma conexão completa de três vias (SYN, SYN-ACK, ACK) com cada porta alvo. É usado quando o Nmap não tem permissões de root/administrador.
2. -sS, SYN Scan (Stealth Scan): O SYN Scan é o tipo de scan mais comum e rápido. Ele envia apenas um pacote SYN e espera uma resposta SYN-ACK para indicar que a porta está aberta. Se uma porta está fechada, normalmente retornará um RST. Este scan não completa a conexão, tornando-o menos detectável.
3. -sP, Ping Scan: O Ping Scan é usado para descobrir quais hosts estão ativos em uma rede. O Nmap envia pacotes ICMP (ping) para verificar se o host responde, sem escanear portas
4. -sF, FIN Scan: O FIN Scan envia um pacote TCP com o flag FIN (finalização) ativado. Se uma porta estiver fechada, o host deve responder com um pacote RST (reset). Se estiver aberta, não haverá resposta. Este scan pode ser útil para passar por firewalls que bloqueiam scans SYN.
5. -sN, Null Scan: O Null Scan envia pacotes TCP sem flags ativadas. Se uma porta está fechada, o host deve responder com um pacote RST. Se estiver aberta, não haverá resposta. É outra técnica para evitar firewalls que filtram SYN scans.
6. -sV, Version Detection: A opção -sV tenta detectar a versão dos serviços que estão rodando nas portas abertas. Isso é útil para identificar vulnerabilidades ou entender mais sobre o alvo.


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

## 1.7 Programas maliciosos
Malware é um programa, ou um programa que se auto reproduz, o qual tem:
- Características ou propósitos ofensivos
- Instala a si mesmo sem a permissão do usuário.
- Afeta a confidencialidade, integridade e disponibilidade.
- É capaz de incriminar erroneamente o dono do sistema, ou usuário, por causa da realização de um crime ou um ataque.

### 1.7.1 Vírus
Um programa que pode infectar outros programas, modificando eles para incluir um possível copia dele mesmo. Vírus são pedaços de código que se adiciona em outros programas, incluindo sistemas operacionais. Não por executar independentemente. Ele precisa de um hospedeiro seja executado para ativá-lo. 
### 1.7.2 Worms
Percorre uma rede, procurando por sistemas vulneraveis. Ele se auto replica e é automático. Normalmente, não precisa de interação humana.
### 1.7.3 Trojans
Passa por um programa legítimo. Parece real, mas esconde seu propósito malicioso. Provoca o usuário a executá-lo, seja por medo, ou curiosidade.
### 1.7.4 Keyloggers
Captura teclas e posição do mouse através de screenshots. Coleta informações sensíveis. Como senhas, PIN's, dados pessoais, documentos, cartão de crédito etc. Pode permanecer invisível ao sistema.
### 1.7.5 Bot or Zombie
Esperam comandos de um mestre. Promove ataques contra terceiro. Instruções podem ser dadas via IRC/IM chats, HTTP methods, P2P etc. Usualmente é usado em ataques de DDoS. São vendidos em mercado negros.
### 1.7.6 Rootkit
Conjunto de ferramentas para hack usadas depois de um atacante ter quebrado um sistema para ganhar acesso de root.

### 1.7.7 Backdoors
Permite que um atacante ultrapasse controle de segurança normais. Mira prover acesso escondido para um atacante ou uma aplicação. Pode ser um comnado, ou uma combinação de chaves para acessar um recuros num software. Tipos de acesso:
- Escalada de privilégio local
- Execução de comandos remotos individuais.
- Acesso a linha de comando remotamente
- Controle do GUI remotamente.
O comando netcat é muito útil para criar um backdoor, ele é com se fosse um canivete suíço. Um exemplo seria:
```bash
nc -l -p 1337 -e /bin/bash
```
Esse comando é usado para criar uma backdoor:
- **nc**: Refere-se ao Netcat, uma ferramenta de rede que pode ler e escrever dados através de conexões de rede usando os protocolos TCP ou UDP.
- **-l**:  Inicia o Netcat em modo de escuta (listen), ou seja, ele vai aguardar conexões.
- **-p 1337**: Especifica a porta em que o Netcat vai escutar. No caso, a porta 1337.
- **-e /bin/bash**: Especifica que, quando uma conexão for estabelecida, o Netcat executará o programa **/bin/bash**. Isso significa que o Netcat vai criar um shell Bash, o que pode permitir ao atacante executar comandos remotamente.

## Exemplo do wideshark










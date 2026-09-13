# ADR-0028 — Inventário de recursos e escrita direta de saldo

Status: aceita e implementada para leitura do inventário de recursos e escrita
direta de saldo. Concessão nativa, remoção, invocação SLI e execução Lua
continuam pendentes (ver "O que não foi implementado").

## Contexto

A reflexão nativa ([ADR-0027](0027-santa-monica-native-reflection.md)) descreve
`tResourcesPerm`, mas o saldo do jogador não é um tipo refletido. Na instalação
Steam 11168363 a investigação encontrou:

- duas globais em `.data` **endereçadas por instruções do jogo**
  (`RVA 0x502A4B0` e `RVA 0x507B450`, mesmo valor) que apontam para um array de
  conjuntos de carteira de 0x50 bytes; o código lê o número de conjuntos em
  `RVA 0x2D439D4` (6) e usa o primeiro;
- no conjunto: `+0x10` store de registros e `+0x20` contagem (1.676);
- registro de 64 bytes acessado pelo próprio código como `[conjunto+0x10] + idx<<6`:
  `+0x00..0x1F` bitset de flags, `+0x28` ponteiro para `Resources[idx]`,
  `+0x30` quantidade `int32`, `+0x34` ordem de aquisição, `+0x38` estado
  (`3` adquirido; `2` nunca adquirido, com quantidade `-1`);
- `ResourcesPerm` fica imediatamente antes de `Resources.data` (`data - 0x78`),
  e seu `{data, size}` precisa concordar com o store.

A versão anterior desta ADR previa PID e endereço absoluto do array na
configuração. Foi descartada: endereço de heap não sobrevive a um reinício, e o
slot `RVA 0x14261C0`, que também apontava para o store, não é referenciado por
nenhuma instrução — é arena de dados, não variável.

## Decisão

### Perfil

O perfil server-side ganha um 16º campo opcional, `resources_root_rva`
(hexadecimal; `0` não publica recursos), que precisa ser um slot de 8 bytes
dentro do módulo. O digest do perfil cobre o campo. O layout acima pertence à
família `gow2018-reflection-x64-v2` no código, nunca à configuração nem à
requisição. Um perfil de nove ou quinze campos não publica recursos.

### Leitura

`read_resource_inventory` parte do módulo validado por nome e tamanho e faz duas
passadas estruturais. Conjunto, store, contagem, cabeçalho de `ResourcesPerm` e
bytes das definições precisam ser idênticos nas duas; senão
`resource_snapshot_changed`. Quantidades e estados vêm da segunda passada,
porque um jogo em andamento os altera legitimamente. Cada registro precisa se
ligar a `Resources[i]`; estado fora de `{2, 3}` ou incoerente com a quantidade
falha. Nomes técnicos são UTF-8 bem formado, sem controles, até 256 bytes, lidos
em blocos que não cruzam página, e únicos — a build real tem nomes não ASCII,
então validação só ASCII rejeitaria o inventário inteiro. Tetos: 4.096 entradas,
8 MiB lidos, deadline de 5 s e cancelamento entre fragmentos. Falha não publica
snapshot parcial.

O resultado é cópia de valores, em cache por contexto com geração própria; o
lock protege só a troca do ponteiro, nunca I/O. `refresh` relê e torna tokens
anteriores obsoletos; o token é vinculado a sessão, contexto, filtro,
`acquired_only` e geração. A resposta declara `validated_best_effort` e
`mutation_safe: false`. Nomes são técnicos: o id de localização é exposto, o
texto não é resolvido, porque não há raiz comprovada para o índice id→texto.

### Escrita direta de saldo

`santamonica_runtime_set_resource` escreve **somente** o `int32` de quantidade
de um recurso já adquirido, localizado por nome técnico exato. Gates: escrita
habilitada no servidor, frase de confirmação por chamada e sessão `read_write`.
O domínio recusa quantidade negativa, acima de 32 bits, acima de `Max` quando
há teto, e recurso nunca adquirido — nesse caso tag de estado, ordem de
aquisição e flags não seriam criados por uma escrita de quantidade.
Imediatamente antes de escrever, ligação e estado são relidos; depois,
quantidade e ligação são relidas. A resposta traz `previous`, `requested`,
`observed`, `verified`, `mechanism: "direct_balance_write"` e
`engine_transaction: false`, e o cache do contexto é invalidado.

Riscos aceitos e declarados: a thread do jogo pode escrever o mesmo slot entre a
revalidação e a escrita; componentes que reagem a um pickup não são disparados;
persistência depende de o jogo salvar. Não existe fallback que transforme
concessão em escrita, nem busca alternativa quando a cadeia não valida.

## O que não foi implementado

Concessão nativa, remoção, invocação SLI e Lua exigem executar código na thread
do jogo. A bridge da ADR-0021 só prova carregamento: faltam dispatcher em tick
validado, bootstrap de segredo sem stdin, instalação e remoção seguras de hook e
contenção de falha. A engenharia reversa estática das funções que usam a raiz
encontrou um comparador de registro (`RVA 0x6D7370`) e um teste de flags
(`RVA 0x6D73F0` → `0x8BDEC0`), não um setter nativo; a concessão provavelmente
passa pelos componentes `resources::components::*`. Nada disso é chamado.
Injetar ou alterar código no processo do operador exige validação prévia em
alvo controlado e confirmação explícita, e não foi feito.

## Verificação

- Unitários sintéticos: nomes UTF-8, validação de snapshot, admissão de
  quantidade, leitura fragmentada, perfis e estruturas corrompidas, mudança
  entre passadas, falha de leitura, cancelamento, deadline e localização.
- Contrato MCP: publicação condicionada à raiz, paginação, filtro, refresh,
  token obsoleto, recusa em sessão somente leitura, escrita verificada,
  invalidação de cache e recusas de escrita.
- Instalação autorizada, na sessão viva do operador: 1.676 recursos lidos pelo
  MCP em 0,67 s, quantidades iguais à leitura direta, escrita idempotente
  verificada e recusas reais. Detalhes em
  [evidência Steam 11168363](../engines/gow2018-steam-11168363-evidence.md).

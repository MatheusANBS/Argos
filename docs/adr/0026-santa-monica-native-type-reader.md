# ADR-0026 — Reader nativo da tabela de tipos Santa Monica

Status: histórico do primeiro reader; substituído pela
[ADR-0027](0027-santa-monica-native-reflection.md). As conclusões abaixo sobre
ausência de campos/herança foram refutadas por evidência posterior. A família
antiga não deve ser usada com o reader atual; migre família e RVAs juntos.

## Contexto

A coleta registrada na [evidência da build](../engines/gow2018-steam-11168363-evidence.md)
encontrou, na imagem do jogo, um registro de tipos do próprio engine: uma
tabela contígua de registros de 80 bytes, cada um com ponteiro para o nome
(`t<Nome>`), ponteiro para o nome de exibição, **tamanho** e **alinhamento**.

O que essa tabela **não** tem: lista de membros. Nomes e offsets de campo não
foram localizados, e as tabelas de hash vizinhas sugerem que membros sejam
endereçados por hash de 64 bits. Enums e assinaturas SLI também não aparecem.

Ou seja: dá para publicar tipos reais desta build, e não dá para publicar
reflexão de campos. A decisão abaixo entrega o primeiro sem fingir o segundo.

## Decisão

Um segundo reader implementa a mesma porta de domínio
`SantaMonicaRuntimeReader`, lendo a tabela **direto da sessão de depuração
autorizada** — sem bridge, sem peer, sem código no alvo, somente leitura.

O caminho é escolhido pelo servidor, nunca pela requisição: se algum perfil de
build casar com um módulo carregado na sessão, a descoberta é nativa; caso
contrário cai no peer controlado da [ADR-0025](0025-santa-monica-local-channel.md).
A resposta declara a origem em `source` (`native-type-table` ou
`controlled-synthetic`), para que nenhum cliente confunda as duas.

### Origem do snapshot no domínio

`ProfileIdentity` ganha `SnapshotSource { bridge, native_reader }`, e o
validador passa a exigir exclusividade nos dois sentidos: um perfil de bridge
tem de carregar identidade de bridge, e um perfil nativo **não** pode carregar
nenhuma. Sem isso, um caminho poderia se apresentar como o outro. O byte de
origem entra no enquadramento da [ADR-0023](0023-santa-monica-reflection-stream.md),
logo após a arquitetura; valor desconhecido é `invalid_snapshot_source`.

### Perfil de build

O layout do registro é uma **família embutida** (`gow2018-typetable-x64`):
passo e offsets são propriedade da build, não configuração. Um `profile_id`
que o servidor não conhece é `unsupported` — não há fallback que adivinhe
formato.

A localização é um **perfil de build do operador**, em
`ARGOS_MCP_SANTAMONICA_BUILD_PROFILES`, com nove campos por registro:

```
build_id|profile_id|module_name|module_size|module_sha256|table_begin|table_end|names_begin|names_end
```

Tamanho em decimal, RVAs em hexadecimal, digest em 64 hex. O parser recusa
campo inválido, faixa invertida, faixa fora do módulo, digest fora de 32 bytes,
nome de módulo com caminho e build_id duplicado. O cliente MCP não fornece,
não escolhe e não lê esse perfil.

A identidade do perfil (`profile_digest`) é o SHA-256 do texto canônico do
registro, obtido do provedor do sistema: editar qualquer campo muda a
identidade de todo snapshot lido sob ele.

### O que o reader garante e o que não garante

Antes de confiar em um único RVA do perfil, o reader confere que o módulo
nomeado está carregado **e** que o tamanho da imagem bate com o declarado.
Cada registro é validado individualmente: ponteiro de nome dentro da faixa de
nomes, nome terminado e ASCII imprimível dentro do teto, tamanho entre 1 e
1 MiB, alinhamento potência de dois até 128. Slot que falhe é pulado e
**contado**, nunca adivinhado.

O id de cada tipo é um digest FNV-1a de 64 bits do nome — estável entre
descobertas da mesma build e, deliberadamente, **não** um endereço. O id do
próprio engine não serve: nesta build há ids duplicados e um id zero.

O digest do módulo no perfil é a **afirmação do operador** sobre o arquivo,
não atestação da imagem carregada. Por isso o snapshot é sempre
`validated_best_effort`, nunca `stable`, e `coverage_complete` é sempre
**falso**: campos, enums e entradas SLI não são cobertos, e as páginas
correspondentes vêm vazias em vez de inventadas.

Inferir herança a partir do RTTI do compilador seria misturar dois universos
de tipo diferentes — classes C++ de um lado, tipos de dado do engine do
outro —, então nenhum vínculo de base é emitido.

## Limites

Este ADR não entrega reflexão de campos, enums, SLI, inventário, gameplay nem
Lua. Não valida a imagem carregada contra o arquivo, não lê o heap e não
escreve nada. Suporte a outra build exige outro perfil do operador e outra
coleta de evidência; a família de layout embutida vale para o formato de
registro observado, não para qualquer build Santa Monica.

## Verificação

Fixtures sintéticas com o mesmo formato de registro cobrem: leitura íntegra
admitida pelo catálogo do domínio, cobertura sempre incompleta, ausência de
herança inventada, slots inválidos pulados e contados (tamanho zero,
alinhamento não potência de dois, ponteiro fora da faixa, ponteiro nulo, nome
sem terminador), módulo ausente, imagem de outro tamanho, família desconhecida,
perfil com faixa fora do módulo ou sem digest, teto de registros, cancelamento,
uso indevido de estado e redação de erro nativo. O parser de perfil e a
autorização têm testes próprios.

Validação de ponta a ponta contra a build do operador, pelo servidor MCP real:
1.192 tipos publicados, nomes e ids únicos, paginação em três páginas,
`source: native-type-table`, `coverage_complete: false`, `fields: 0`,
`enums: 0`, `sli_functions: 0`.

Referências: [ADR-0023](0023-santa-monica-reflection-stream.md),
[ADR-0025](0025-santa-monica-local-channel.md),
[Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md),
[evidência da build](../engines/gow2018-steam-11168363-evidence.md).

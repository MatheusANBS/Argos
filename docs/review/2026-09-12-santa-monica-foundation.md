# Revisão — fundação Santa Monica/Kinetica

Data: 2026-09-12. Plano aprovado pelo operador; primeiro incremento concluído
no domínio, sem declarar implementada a Spec 0014 inteira.

## Entrega

- Identidade de perfil com versão, arquitetura x64, digests tipados e lista
  canônica de módulos; nenhum perfil executável é distribuído.
- Porta `SantaMonicaRuntimeReader` e catálogo imutável de registros
  normalizados de tipos, campos, enums/valores e funções SLI descritivas.
- Admissão integral com limites de quantidade, strings e capacidade retida,
  validação de duplicatas/referências/herança/bounds e preservação de valores
  inteiros de 64 bits. Identidade alterada, erro ou cancelamento não publica
  catálogo; cobertura incompleta declarada pelo reader permanece explícita.
- Evidência somente leitura do arquivo disponibilizado pelo operador,
  [Steam build 11168363](../engines/gow2018-steam-11168363-evidence.md).

## Verificação executada

Build MSVC 14.51, C++23, `/W4 /permissive-`, presets `dev` e `asan`: sem novos
warnings. CTest passou em **5/5 targets** nos dois presets, incluindo os
targets existentes e `argos_santa_monica_runtime_tests`.

Os testes novos cobrem catálogo vazio, 100.000 registros, limite exato de
bytes e quantidade, excesso de capacidade reservada, ciclos/herança profunda,
IDs/nomes duplicados, referências ausentes, overflow de campos, tamanho de
ponteiro/objeto, enum fora de faixa, mudança de processo/época/geração/perfil,
cancelamento e redação de erros do reader. O catálogo permanece válido após
destruição do reader. O contrato MCP verifica ausência de tools Santa Monica
nas duas eras do protocolo.

Nesta toolchain o preset `asan` instrumenta **ASan somente**; UBSan e TSan
não foram executados. Não foi executada build Linux nesta entrega. Os testes
sintéticos não medem custo de tick no jogo nem substituem a validação de uma
build real.

## Revisão de contratos e limites

O domínio usa apenas biblioteca padrão e tipos do domínio, sem MCP/JSON/OS,
logging ou dependência externa nova. Ownership do catálogo é exclusivo e sua
API expõe somente acesso const. Índices temporários guardam referências
apenas durante a validação e são ordenados com custo limitado pelo número de
registros. Aritmética de orçamento e bounds usa subtração/divisão antes de
somar/multiplicar valores externos. Não há threads, locks, writes, execução
no alvo, unload ou saída em `stdout` introduzidos por esse incremento.

Comparar identidades não autentica uma bridge: a porta exige que uma futura
infraestrutura valide peers, arquivo/imagem, quotas antes do decode e limites
de trabalho nativo. `stable` é uma garantia fornecida por essa fronteira, não
inferida de releituras iguais. O schema de identidade ainda não contém os
layouts/assinaturas e a política de normalização da imagem carregada. Arrays e
mapas têm descrição inicial; parsing nativo e validação de layouts completos
permanecem pendentes.

O reader é de uma única descoberta; seu dono deve destruí-lo ao concluir ou
abortar para liberar estado nativo parcial. Os limites implementados cobrem um
catálogo, não a quota agregada/TTL do manager futuro. O canal IPC autenticado,
dispatcher, manager, paginação opaca e integração MCP permanecem trabalho
posterior, conforme a [Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md).

## Segundo incremento — stream de reflexão

Entrega: formato de transferência do snapshot e seu leitor
([ADR-0023](../adr/0023-santa-monica-reflection-stream.md)), em
`argos_infrastructure`. `encode_reflection_frame` produz frames binários
versionados little-endian, campo a campo, sem struct nativa, ponteiro ou
padding no wire; `ReflectionStreamReader` implementa a porta do domínio sobre
`ReflectionByteStream`, que isola o transporte.

O reader valida magic, versão, comprimento de header, kind, reservado, request
e sequência antes de dimensionar o corpo, e recusa frame acima de 1 MiB, budget
agregado de 64 MiB, mais de 100.000 registros ou deadline de 5 s — a
configuração só reduz esses tetos. Strings têm comprimento validado contra o
teto negociado e os bytes restantes antes de qualquer alocação, exigem ASCII
imprimível sem NUL e separam identidade (128 bytes) de metadados (4 KiB).
Fragmentação arbitrária é aceita, EOF prematuro é erro, cancelamento e deadline
são conferidos antes e depois de cada leitura, e a primeira falha invalida a
instância e fecha o stream. Consumir `end` também fecha: bytes posteriores
nunca são interpretados.

Verificação executada: build MSVC 14.51, C++23, `/W4 /permissive-`, presets
`dev` e `asan`, sem novos warnings; CTest passou em **6/6 targets** nos dois
presets, incluindo o novo `argos_santa_monica_stream_tests`. Os testes montam
bytes por conta própria, independentes do encoder, e cobrem os bytes do header,
round-trip de todas as variantes e field kinds, integração com
`ReflectionCatalog`, fragmentação de 1 byte, truncamento, EOF, comprimentos
excessivos, versões/tags/bools/enums inválidos, payload residual,
request/sequência incorretos, frame na posição errada, replay do frame de
abertura, budget agregado, deadline com relógio controlado, cancelamento,
mau uso de estado, limites inválidos e fechamento em erro e em sucesso.

Revisão: o codec não usa JSON, MCP, OS, threads, locks ou dependência externa,
e o domínio continua recebendo apenas registros tipados. Aritmética de budget
subtrai antes de somar, mantendo `wire_bytes_ <= max_wire_bytes`. O buffer de
decode é reutilizado e limitado a um frame. Diagnóstico nativo do transporte é
reduzido a razões fixas, e o domínio ainda normaliza os erros do reader.

Limites honestos: este incremento não instala transporte. Handshake, ACL,
bootstrap com segredo/época e validação da imagem carregada continuam
pendentes, portanto um decode íntegro não autentica o peer, e request/sequência
detectam troca e repetição apenas dentro do stream. `stable` permanece uma
garantia da fronteira nativa. Nenhuma tool MCP foi anunciada.

## Terceiro incremento — handshake autenticado

Entrega: autenticação mútua do canal
([ADR-0024](../adr/0024-santa-monica-bridge-handshake.md)). No domínio,
`BridgeSecret` com armazenamento fixo e zeroização, transcript canônico com
rótulo por direção, `constant_time_equal`, negociação de capacidades por
conjunto fechado e `BridgeHandshakeServer` de uso único. Na infraestrutura,
HMAC-SHA-256 e nonces do provedor do sistema por CNG (`bcrypt.lib`, biblioteca
do sistema, sem dependência externa nova) e o enquadramento `SMBH`. Os dois
codecs passaram a compartilhar as primitivas de bytes em
`src/infrastructure/detail/wire_bytes.hpp`.

A ordem de verificação é deliberada: checagem estrutural do que o peer escolheu
para si, depois a tag e só então a comparação de identidade, com motivo único.
Assim nenhum peer sem o segredo obtém oráculo sobre a identidade esperada, e um
peer honesto com época errada recebe uma resposta precisa. A concessão é
subconjunto da oferta e do pedido, e a tag de accept cobre o concedido.

Verificação executada: build MSVC 14.51, C++23, `/W4 /permissive-`, presets
`dev` e `asan`, sem novos warnings; CTest passou em **7/7 targets** nos dois
presets, incluindo `argos_santa_monica_bridge_tests`. Os testes cobrem
transcript byte a byte e sua sensibilidade a cada campo vinculado sem colisões,
segredo errado, rótulo e nonce trocados, nonce espelhado ou nulo, capacidade e
versão alteradas depois de assinadas, tag adulterada, identidade divergente,
binding inválido, CSPRNG indisponível ou degenerado, ordem e uso único do
estado, attestation de outro handshake, zeroização conferida no armazenamento
do objeto após a destruição, bytes dos quatro frames, round-trip, e recusa de
magic, versão, header, kind, reservado, request, sequência, frame acima do
teto, truncamento, excedente, payload residual e motivo de reject desconhecido.

Sobre a primitiva: nenhum vetor publicado de HMAC-SHA-256 usa chave dentro do
piso de 32 bytes adotado aqui, então a verificação é cruzada — o SHA-256 do
provedor é comparado ao valor publicado de `"abc"`, e o HMAC do provedor é
comparado à construção RFC 2104 sobre esse mesmo hash, com chaves de 32, 48 e
64 bytes. Isso não substitui uma suíte CAVP completa.

Limites honestos: o canal continua sem existir. Named pipe, ACL restrita ao
usuário, recusa de acesso remoto, canal de bootstrap do segredo, validação da
imagem carregada, heartbeat, fila e dispatcher permanecem pendentes, e a única
capacidade negociável é `reflection_read`. A zeroização é feita por escrita
volátil: ela apaga o objeto, não cópias que um alocador ou o SO tenham feito
antes. O lado da bridge (`tools/debug_bridge.cpp`) ainda não implementa o
handshake. Nenhuma tool MCP foi anunciada.

## Quarto incremento — canal, manager e tools (etapa 1 fechada)

Entrega: o restante da etapa 1, contra um alvo sintético
([ADR-0025](../adr/0025-santa-monica-local-channel.md)).

- Infraestrutura: `LocalBridgeChannel` — named pipe local de instância única,
  criado antes de existir peer, com `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS` e DACL protegida contendo apenas o SID do
  usuário atual; verificação do PID do par; I/O overlapped com deadline e
  cancelamento em fatias, cancelando e drenando antes de liberar buffers.
  `BridgePeerProcess` lança o peer configurado pelo operador e entrega o
  segredo pela stdin do filho. `serve_bridge_peer` e `read_bridge_snapshot`
  são os drivers dos dois lados, compartilhados por testes e pelo peer.
- Domínio: `BridgeHandshakeClient`, o par simétrico do servidor, com a mesma
  disciplina de uso único, mais `secure_zero` exposto para quem segura material
  sensível fora do domínio.
- Aplicação: `SantaMonicaRuntimeManager` com quotas por dono e globais, TTL,
  release idempotente por janela de tombstone, invisibilidade entre sessões e
  um único dono vivo por instância de processo e época (`runtime_busy`).
  `memory_debug_service_santamonica.cpp` conduz a descoberta e as consultas.
- Policy: gate `ARGOS_MCP_ENABLE_SANTAMONICA_RUNTIME` mais
  `ARGOS_MCP_SANTAMONICA_PEER` (caminho absoluto, existente, escolhido pelo
  operador), com tetos próprios que uma requisição só reduz.
- MCP: seis tools somente leitura, ausentes de `tools/list` sem gate **e** peer.
  Paginação por token opaco vinculado a sessão, contexto, época, filtro e tool;
  ids de metadados como strings decimais opacas, nunca endereços nem números
  JSON; valores de enum com grafia decimal exata; `invocable: false` sempre.
- Ferramenta: `tools/santa_monica_peer.cpp`, o peer controlado. Ele fala o
  protocolo real e fabrica os metadados; não lê, inicia nem injeta em nada.

Verificação executada: build MSVC 14.51, C++23, `/W4 /permissive-`, presets
`dev` e `asan`, sem novos warnings; CTest passou em **8/8 targets** com ASan,
incluindo o novo `argos_santa_monica_channel_tests` e o contract test, que
agora exercita a cadeia inteira — `tools/list` → `attach` → `discover` (que
cria o pipe, lança o peer real, entrega o segredo, autentica e lê o snapshot) →
`types` paginado → `type` com herança → `enums` → `sli_functions` → `release`
→ nova descoberta. Os testes cobrem ainda: endpoint sem peer até o deadline,
endpoint inexistente, PID divergente, leitura com peer mudo, cancelamento
durante I/O, segredo errado, época divergente, token de outra consulta,
contexto de outra sessão e consulta após release.

Revisão: o domínio continua sem Win32, JSON, MCP ou relógio; todo handle
nativo tem wrapper RAII; o segredo é apagado no servidor logo após criar a
chave e no peer logo após lê-la; erros de transporte e de handshake chegam ao
cliente como razões fechadas. O `stdout` do servidor continua exclusivo do
protocolo — o peer escreve apenas em `stderr`.

Limites honestos, e eles são grandes: **o peer é sintético**. Ele prova o
protocolo de ponta a ponta, não compatibilidade com *God of War* (2018). Não
existe perfil de build real, parser RTTI/SLI nativo, bridge injetada que fale
o protocolo, validação da imagem carregada, heartbeat, fila ou dispatcher —
e portanto nada de inventário, gameplay ou Lua. As etapas 2 a 5 continuam
dependendo da evidência por build da etapa 0. O `session_id` é âncora de posse,
não descreve o processo de onde vieram os dados. Uma capacidade adicional
tornaria alcançável o ramo `capability_unavailable` do cliente, hoje inerte por
existir uma única capacidade.

Fora deste escopo, mas encontrado durante a verificação: `argos_unit_tests`
falha de forma intermitente (cerca de 1 em 4 execuções sob ctest) em "the sync
scan path recovers once no job is running for the session". A causa está no
`AnalysisJobManager`: o worker publica o estado terminal dentro de `run_job` e
só depois apaga o dono de `running_owners_`, então existe uma janela em que um
job terminal e já liberado ainda faz `has_running_job` responder verdadeiro e
o scan síncrono ser recusado com `analysis_job_active`. É defeito visível pelo
cliente, anterior a este trabalho e em subsistema não tocado aqui; ficou
registrado como tarefa separada em vez de corrigido junto.

## Quinto incremento — reader nativo da build real

Entrega: o servidor deixou de depender do peer sintético para publicar
reflexão. Com um perfil de build do operador, ele lê a tabela de tipos do
próprio engine direto da sessão de depuração autorizada
([ADR-0026](../adr/0026-santa-monica-native-type-reader.md)).

- Domínio: `ProfileIdentity` ganha `SnapshotSource { bridge, native_reader }`,
  e o validador passa a exigir exclusividade nos dois sentidos — perfil de
  bridge tem de carregar identidade de bridge, perfil nativo não pode carregar
  nenhuma. Sem isso, um caminho poderia se apresentar como o outro. O byte de
  origem entra no enquadramento da ADR-0023.
- Infraestrutura: `NativeTypeTableReader` implementa a mesma porta
  `SantaMonicaRuntimeReader`, lendo por `RuntimeMemoryView`. A família de
  layout é embutida (`gow2018-typetable-x64`); só a localização vem de perfil.
  Acrescentou-se `sha256` do provedor do sistema para derivar a identidade do
  perfil a partir do seu texto canônico.
- Policy: `SantaMonicaBuildProfile` e o parser de
  `ARGOS_MCP_SANTAMONICA_BUILD_PROFILES`, com nove campos, faixas ordenadas e
  dentro do módulo, digest de 32 bytes e build_id único. O gate passou a
  aceitar **qualquer** das duas origens; a validação do caminho do peer migrou
  para onde o peer é de fato lançado.
- Aplicação: `discover` tenta o caminho nativo primeiro e cai no peer quando
  nenhum perfil casa. A escolha é do servidor, nunca da requisição, e a
  resposta declara `source`.

Ordem de confiança deliberada: o módulo nomeado precisa estar carregado **e**
ter o tamanho declarado antes que um único RVA do perfil seja usado. Depois,
cada registro é validado sozinho — ponteiro de nome dentro da faixa, nome
terminado e imprimível, tamanho entre 1 e 1 MiB, alinhamento potência de dois —
e o slot que falha é pulado e **contado**.

Duas decisões que evitam mentira no contrato: `coverage_complete` é sempre
falso no caminho nativo, porque campos, enums e SLI não existem nessa tabela; e
nenhum vínculo de herança é emitido, porque juntar o RTTI do compilador com os
tipos de dado do engine seria misturar dois universos diferentes.

O id de tipo é digest FNV-1a do nome, não o id do engine: nesta build há ids
duplicados e um id zero, então o id nativo não serve como chave. O digest do
nome é estável entre descobertas e não é endereço.

Verificação executada: build MSVC 14.51, C++23, `/W4 /permissive-`, presets
`dev` e `asan`, sem novos warnings; CTest em **9/9 targets**, incluindo o novo
`argos_santa_monica_native_tests`. As fixtures sintéticas reproduzem o formato
de registro e cobrem leitura íntegra, cobertura sempre incompleta, ausência de
herança inventada, seis formas de slot inválido, módulo ausente, imagem de
outro tamanho, família desconhecida, perfil fora do módulo ou sem digest, teto
de registros, cancelamento, uso indevido de estado e redação de erro nativo. O
parser de perfil e a autorização têm testes próprios.

Validação de ponta a ponta contra a build do operador, dirigindo o **servidor
MCP real** por stdio: seis tools anunciadas, `discover` publicando **1.192
tipos** com `source: native-type-table`, `coverage_complete: false`, `fields:
0`, `enums: 0`, `sli_functions: 0`; filtro por nome devolvendo `tRecipeItem`
(32 B), `tRecipe` (64 B), `tRecipesPerm` (32 B) e `tWalletRecipeCondition`
(88 B); paginação completa em três páginas com 1.192 nomes e 1.192 ids únicos,
sem colisão; e `release` idempotente. Uma auditoria de todos os nomes
publicados mostrou que os dez que não seguem o padrão `t<Maiúscula>` são tipos
legítimos (`SlashWound`, `WeaponEmbedPoints`, `EmbedPoint`, `ConfigSpec`…), ou
seja, o reader é mais completo que a heurística exploratória, não mais frouxo.

Limites honestos: isto publica **tipos e tamanhos**, não reflexão de campos. A
build não expõe nome nem offset de membro, e as tabelas de hash vizinhas
sugerem endereçamento por hash de 64 bits; achar o layout de campos exige
desmontar a rotina de registro, que é engenharia reversa sustentada e não foi
feita. O digest do módulo no perfil é afirmação do operador sobre o arquivo,
não atestação da imagem carregada — daí `validated_best_effort` e nunca
`stable`. Nenhum perfil é distribuído com o repositório; o do operador foi
usado apenas para validar. Inventário, gameplay e Lua continuam fora.

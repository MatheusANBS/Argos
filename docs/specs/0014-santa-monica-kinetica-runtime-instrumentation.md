# Spec 0014 — Runtime Santa Monica/Kinetica: reflexão, Lua e gameplay

## Status

Plano aprovado em 2026-09-12; implementação incremental em andamento.
Seis tools de reflexão somente leitura são anunciadas quando o gate e uma
origem do operador estão configurados. Com raiz de recursos no perfil, o
inventário de recursos e a escrita direta de saldo também existem (ADR-0028).
Concessão nativa, invocação SLI e Lua continuam indisponíveis.

Revisão do plano: 2026-09-12. A evidência pública sustenta investigação, não
uma build já suportada. O primeiro incremento é reflexão somente leitura;
gameplay e Lua dependem de provas separadas, conforme as etapas abaixo.

### Progresso de implementação

O primeiro incremento implementa `domain::santamonica::ProfileIdentity`, a
porta `SantaMonicaRuntimeReader` e `ReflectionCatalog::read`, com testes
sintéticos independentes. O catálogo valida identidade antes/depois, limites
de registros/strings/capacidades retidas, IDs duplicados, herança, bounds de
campos e referências a tipos/enums. Enum de 64 bits mantém representação
decimal exata. Erros/cancelamento não publicam catálogo parcial; cobertura
parcial declarada permanece visível. Nomes são ASCII imprimível nesta base;
outro encoding requer contrato explícito no adapter.

O segundo incremento implementa o formato de transferência do snapshot
([ADR-0023](../adr/0023-santa-monica-reflection-stream.md)): frames binários
versionados com codec e `ReflectionStreamReader` em `argos_infrastructure`.
O reader valida magic, versão, comprimentos, reservados, request e sequência
antes de alocar o corpo; aplica budget agregado, teto de registros e deadline;
aceita fragmentação arbitrária; trata EOF prematuro como erro; e fecha o
stream tanto na conclusão quanto na primeira falha, que invalida a instância.
Ele alimenta `ReflectionCatalog` sem contornar nenhuma validação do domínio e
não instala transporte: handshake, ACL, segredo/época e validação da imagem
carregada continuam pendentes, então um decode bem-sucedido não autentica peer
nem impede replay entre conexões.

O terceiro incremento implementa o handshake autenticado
([ADR-0024](../adr/0024-santa-monica-bridge-handshake.md)): segredo efêmero
por sessão com zeroização, transcript canônico com separação de domínio,
verificação em tempo constante, negociação de capacidades por conjunto fechado
e `BridgeHandshakeServer` de uso único no domínio; HMAC-SHA-256 e nonces do
provedor do sistema (Windows CNG) e enquadramento `SMBH` na infraestrutura.
Identidade declarada só é comparada depois da prova, e a divergência responde
com um motivo único. Continua sem transporte: named pipe, ACL, recusa de
acesso remoto, canal de bootstrap, validação da imagem carregada, heartbeat,
fila e dispatcher permanecem pendentes, e a capacidade negociada nesta versão
é apenas `reflection_read`.

O quarto incremento fecha a etapa 1 contra um alvo sintético
([ADR-0025](../adr/0025-santa-monica-local-channel.md)): canal local por named
pipe com instância única, ACL restrita ao usuário, recusa de cliente remoto,
verificação do processo par, I/O com deadline e cancelamento, e bootstrap do
segredo pela stdin do peer — nunca por argv, ambiente ou log. Sobre ele
existem o `SantaMonicaRuntimeManager` na aplicação (quotas por dono e globais,
TTL, release idempotente por janela, e um único dono vivo por instância de
processo e época) e seis tools MCP somente leitura atrás de gate próprio, com
paginação por token opaco vinculado a sessão, contexto, época, filtro e tool.

O peer é controlado e sintético: ele fala o protocolo real e transmite
metadados inventados. Nada nesta etapa lê, inicia ou injeta em um jogo. Perfil
real, bridge injetada, validação da imagem carregada, heartbeat, dispatcher,
inventário, gameplay e Lua continuam pendentes.

O quinto incremento entrega o **reader nativo**
([ADR-0026](../adr/0026-santa-monica-native-type-reader.md)). A coleta na build
do operador localizou o registro de tipos do próprio engine, e o servidor passa
a lê-lo direto da sessão autorizada: sem bridge, sem peer, somente leitura.
Com um perfil de build casando o módulo carregado, `discover` publica tipos
reais da build — nome, tamanho e id estável — e declara `source:
native-type-table`. Sem perfil, continua caindo no peer controlado.

O sexto incremento corrige e amplia esse reader
([ADR-0027](../adr/0027-santa-monica-native-reflection.md)). A família
`gow2018-reflection-x64-v2` usa o início real de TypeDecl, herança, faixas de
atributos do dono, tabelas de enums/valores e funções SLI. O perfil aceita
seis RVAs adicionais e sua identidade cobre todos os campos e o hash do módulo.
O modelo elimina cópias herdadas e views embutidas, distingue enums homônimos
por índice e confina todas as leituras ao módulo. Há tetos antes de alocar,
64 MiB de leitura agregada e deadline cooperativo de 5 s.

Na instalação Steam 11168363, o MCP publicou 1.192 tipos, 7.041 campos próprios,
482 enums, 3.791 valores e 309 funções SLI. Cobertura permanece incompleta:
propriedades SLI, auxiliares de coleções e mapas sem tamanho comprovado não
são representados. `include_inherited` usa os vínculos de base, sem duplicar
as declarações próprias. Arrays/ponteiros de conteúdo sem tipo refletido têm
referência nula; referências presentes devem resolver.

O reader é uma porta interna de confiança, não autenticação por comparação de
campos declarados. Não há atestação da imagem carregada, dispatcher, gameplay
ou Lua executável. O caminho nativo não exige nem instala bridge no jogo.

A identidade do arquivo disponibilizado pelo operador está registrada em
[evidência Steam 11168363](../engines/gow2018-steam-11168363-evidence.md).
Ela documenta a validação de reflexão nesta instalação e os critérios ainda
pendentes para inventário, gameplay, Lua e suporte mais amplo à build.

O sétimo incremento entrega o **inventário de recursos**
([ADR-0028](../adr/0028-santa-monica-resources-and-execution.md)). A raiz é uma
global endereçada pelo código do jogo, informada no 16º campo do perfil; o
reader valida `ResourcesPerm`, a ligação de cada registro e o estado, em duas
passadas estruturais. `santamonica_runtime_resources` pagina os saldos e
`santamonica_runtime_set_resource` escreve a quantidade de um recurso já
adquirido, com os gates de escrita, revalidação e releitura, declarando
`engine_transaction: false`. Na instalação Steam 11168363, 1.676 recursos foram
lidos em 0,67 s e uma escrita idempotente foi verificada. Concessão nativa,
remoção, SLI invocável e Lua continuam pendentes: exigem dispatcher na thread
do jogo, que não existe.

## Objetivo

Para uma build autorizada de *God of War* (2018), fornecer reflexão de RTTI e
SLI, observação/execução Lua, exploração de itens e inventário, além de
concessão/remoção de item pela transação interna da engine. Não é parser
genérico de binários nem executor nativo arbitrário.

## Pré-condições e gates

Todas as tools exigem sessão explicitamente autorizada, mesmo usuário por
padrão e perfil de build validado pelo servidor. O cliente não fornece
assinatura, root, RVA, endereço de função ou layout.

| Gate proposto | Padrão | Libera |
|---|---:|---|
| `ARGOS_MCP_ENABLE_SANTAMONICA_RUNTIME` | `0` | RTTI, SLI descritivo, catálogo e inventário |
| `ARGOS_MCP_SANTAMONICA_PROFILES` | vazio | allowlist de perfis |
| `ARGOS_MCP_ALLOW_SANTAMONICA_EARLY_LOAD` | `0` | Lua durante bootstrap |
| `ARGOS_MCP_ALLOW_SANTAMONICA_GAMEPLAY` | `0` | grant/removal e invocação SLI |
| `ARGOS_MCP_ALLOW_SANTAMONICA_LUA_EXECUTE` | `0` | executar fonte Lua |

Os gates são avaliados somente no startup. Mutações de gameplay e execução Lua requerem
`authorized: true` em cada chamada. A resposta de discover publica as
capacidades de modding que estavam efetivamente habilitadas.

Leituras de inventário e catálogo dependem apenas do gate de runtime e da
capacidade validada; não autorizam mutações. `lua_execute` exige também
gameplay. Cada tool fica ausente quando seus gates necessários estão
desligados, e o dispatcher aplica a mesma policy em chamadas diretas.
Gate ligado não prova suporte: discover retorna por capacidade `available`
e um `reason` seguro quando indisponível. `authorized: true` confirma uma
ação, mas não substitui a autorização e o vínculo da sessão.

`discover` recebe `session_id` e `profile_id` da allowlist, sem carregar DLL
ou iniciar processo implicitamente. Attach que precise de carga usa antes a
Spec 0013, com seus gates de injeção e allowlist. A bridge atual
(`tools/debug_bridge.cpp`) só prova presença; IPC, handshake, hooks e
dispatcher ainda precisam ser implementados. Uma bridge sem esses recursos
retorna `unsupported`, nunca sucesso parcial disfarçado de suporte.

`early_load` é uma etapa posterior: o operador prepara a instalação de teste
e inicia o alvo com a bridge aprovada antes do bootstrap. Discover apenas
valida essa sessão. Automatizar o início exige extensão explícita da
[Spec 0005](0005-managed-process-launch.md), seus gates/allowlists e contrato
de ownership; `launch` seguido de injeção não garante captura do bootstrap.

## Contexto e proveniência

`memory_debug_santamonica_runtime_discover` cria um `runtime_id` opaco após
validar nome, arquitetura, tamanho e fingerprint do módulo, versão da bridge,
assinaturas server-side e estruturas necessárias à capacidade. Em `attach`,
usa bridge Argos pré-aprovada; em `early_load`, a sessão vem de início controlado antes do
runtime Lua. Um perfil divergente retorna `unsupported`.

Toda resposta derivada inclui source, perfil, fingerprint e versão da bridge.
Respostas de snapshot incluem também geração, consistência e completude:

```json
{
  "source": "santamonica:kinetica-runtime",
  "profile_id": "gow2018-pc-<build>",
  "process_fingerprint": "opaque",
  "bridge_version": "1",
  "snapshot_generation": "opaque",
  "snapshot_status": "validated_best_effort",
  "coverage_complete": false
}
```

O fingerprint não revela path ou bytes. A descoberta valida regiões,
alinhamento, limites, índices, strings e referências cruzadas; relê cabeçalhos
e amostras antes/depois. Essas releituras detectam algumas mudanças, mas não
provam atomicidade nem ausência de ABA. `stable` só é válido para cópia feita
sob mecanismo de consistência comprovado pelo perfil (safe point e ausência
de escritores concorrentes, lock ou geração autoritativa). Snapshot instável
não publica catálogo completo e retorna códigos de invariante, nunca RVAs,
padrões ou erros Win32.

O perfil imutável possui versão de schema e digest, identidade SHA-256 do
arquivo executável e dos módulos relevantes, arquitetura, tamanho de imagem,
regras para relocations/ASLR e verificação da imagem carregada. Hash do arquivo
em disco sozinho não atesta a imagem em execução. O fingerprint opaco vincula
instância do processo (incluindo criação, não só PID), perfil, módulos e época
da bridge. Divergência ou reload invalida contextos e handles antes de executar
novos comandos. Layouts e assinaturas vêm de investigação independente com
proveniência registrada; não são copiados da referência sem licença.

### Canal de bridge e ownership

O novo protocolo deve ser fechado, versionado e testado antes de qualquer
operação no alvo. O handshake verifica identidade do servidor/alvo, sessão,
época, digest do artefato Argos aprovado, perfil e capacidades. O transporte
local precisa restringir ACL ao usuário autorizado, rejeitar acesso remoto e
validar o peer; PID/nome de pipe ou versão declarada não bastam. A vinculação
usa segredo efêmero por sessão por canal de bootstrap protegido, nunca em
logs ou argumentos públicos. O modelo não protege contra um alvo já
comprometido nem contra um agente com acesso de depuração equivalente ao alvo.

Frames têm limite antes de alocação, opcode fechado, request ID, sequência e
epoch; rejeitam replay, comprimento inválido, versão divergente e comandos de
outra sessão. Handshake, I/O, heartbeat e fila possuem deadlines e limites.
O formato binário/encoding, ACL e bootstrap exatos são entregáveis da etapa 1,
não contratos já fornecidos pela Spec 0013.

Um `SantaMonicaRuntimeManager` na aplicação possui contextos, snapshots,
handles e registros de operação. As portas `SantaMonicaRuntimeReader` e
`SantaMonicaBridgeChannel` recebem tipos fortes e resultados tipados no domínio.
Infraestrutura possui recursos nativos por RAII; nenhum ponteiro para memória
do alvo sobrevive como referência C++ no servidor. Um único owner por processo
e época serializa Lua, SLI e gameplay, mesmo que haja mais de uma sessão de
depuração para o mesmo PID. A segunda sessão recebe `busy`, sem segunda fila.

## Reflexão

| Tool proposta | Contrato |
|---|---|
| `memory_debug_santamonica_runtime_types` | pagina tipos RTTI com `type_id`, nome, tamanho e base |
| `memory_debug_santamonica_runtime_type` | campos declarados/herdados, offsets, tamanho, kind, array/mapa e enum |
| `memory_debug_santamonica_runtime_enums` | pagina enum e pares nome/valor sem truncamento |
| `memory_debug_santamonica_runtime_sli_functions` | pagina funções/propriedades SLI com assinatura e `invocable` |

Tipos, nomes, strings e tabelas são limitados pela policy antes de
materialização. `page_token` é opaco e vinculado a runtime, filtro e geração.
Callback nativo não é exposto. Uma função só recebe `invocable: true` quando o
perfil conhece ABI, marshaler RTTI e ponto main-thread compatíveis, e autoriza
explicitamente aquela função e seus efeitos. Estar num registry não autoriza
execução; funções desconhecidas continuam `invocable: false`.

Cada página recebe `session_id`, `runtime_id`, filtro, `page_size` e token
opcional; retorna itens, geração, completude, motivos de truncamento e próximo
token. O token vincula também tool/ordenação; expiração ou geração divergente
retorna `stale_snapshot`, sem reiniciar silenciosamente. Páginas percorrem cópia
imutável limitada, não tabelas vivas. Ciclos de herança/referências, overflow de
offset/contagem, short reads e profundidade excessiva falham de forma segura.
Enums grandes são paginados; valores inteiros de 64 bits usam representação
decimal textual quando necessário para evitar perda de precisão no cliente.

`coverage_complete` refere-se ao registry e escopo declarados no perfil, não a
todos os tipos/itens existentes no jogo. `results_complete` informa se tudo
observado foi retido. Limite ou lacuna não vira catálogo completo.

## Lua

`memory_debug_santamonica_runtime_lua_scripts`, disponível apenas em
`early_load`, lista scripts observados com path lógico normalizado, contexto e
digest e cobertura desde o início da observação. A primeira entrega publica
somente metadados, não fonte/bytecode. Exportação e substituição de scripts
ficam para contrato posterior, com limites e revisão próprios.

`memory_debug_santamonica_runtime_lua_execute` executa fonte Lua limitada na
VM do jogo, com gates de runtime, gameplay e Lua. Recebe `session_id`,
`runtime_id`, `source`, `idempotency_key` e `authorized: true`; limites opcionais
apenas reduzem a policy. A bridge agenda o trabalho
no tick validado; não chama Lua na thread MCP. O resultado contém estado,
saída saneada/limitada, digest da fonte e duração. Há limites de bytes,
instruções, memória atribuível à execução e saída. Deadline e cancelamento são
cooperativos; não interrompem com segurança uma chamada nativa bloqueada.

O perfil deve identificar versão/ABI efetiva da VM, ownership, GC, mecanismo
de erro/yield e coexistência com hooks existentes. Não se assume Lua 5.1 nem
compatibilidade com uma biblioteca externa apenas por haver scripts Lua.
O [manual Lua](https://www.lua.org/manual/5.1/manual.html#lua_sethook) ilustra
por que contar instruções Lua não limita tempo dentro de callbacks C; a VM
real precisa ser verificada antes de prometer esse orçamento.

A fonte roda em ambiente de capacidades explícitas, sem acesso transitivo ao
ambiente global, registry/debug, loaders, FFI, filesystem, rede, shell ou
callbacks não aprovados. Apenas remover alguns nomes globais não é uma sandbox.
São aceitos somente texto e wrappers de gameplay permitidos pelo perfil, sem
bytecode cliente. Coroutines, callbacks e referências criados pela operação
permanecem rastreados e são liberados no safe point, sem fechar a VM do jogo.
Se não for possível comprovar isolamento, limites de memória e limpeza para
a build, `lua_execute` permanece indisponível; mod Lua irrestrito exigirá outra
decisão de segurança. Nenhum erro/longjmp atravessa frames C++ com RAII sem
uma fronteira de tradução comprovadamente segura.

## Itens e inventário

| Tool proposta | Contrato |
|---|---|
| `memory_debug_santamonica_runtime_items` | catálogo filtrável de definições de item com `item_id` opaco, categoria, requisitos e evidência |
| `memory_debug_santamonica_runtime_inventory` | snapshot com garantia de consistência explícita, `instance_id`, `item_id`, quantidade, upgrade, flags e slot |
| `memory_debug_santamonica_runtime_grant_item` | concede `item_id` previamente listado, respeitando limites e fluxo interno |
| `memory_debug_santamonica_runtime_remove_item` | remove apenas `instance_id` previamente publicado |

`grant_item` recebe `session_id`, `runtime_id`, `item_id`, `quantity`,
`expected_inventory_generation`, `idempotency_key` e `authorized: true`.
`remove_item` tem os mesmos campos, substituindo `item_id` por `instance_id`.
Quantidade é inteiro positivo limitado por policy e perfil; zero, negativos,
overflow e remoção além do disponível são rejeitados antes da transação.
A bridge usa a criação/concessão interna validada, para que a engine gere
identidade de instância, atualize equipamento/atributos e marque o save. A
spec proíbe construir manualmente uma struct ou escrever uma lista de itens.
O resultado inicial devolve `operation_id`; o resultado terminal informa as
instâncias criadas/alteradas, quantidades efetivas, gerações antes/depois e
`persistence_status` (`not_requested`, `pending`, `confirmed` ou `unknown`).
Grant pode criar várias instâncias ou ampliar uma pilha existente. Retorno da
função e marcação de save não comprovam persistência em disco.

No safe point, a bridge revalida geração do inventário, identidade/lifetime da
instância, jogador/save ativos, quantidade, requisitos e estado da engine
(inclusive loading/save em andamento). Divergência retorna `stale_snapshot`
sem mutação. Handles de instância expiram na troca de save/mundo e após mutação;
o cliente precisa ler novo inventário. Definições de item são vinculadas à
geração do catálogo. Não se promete rollback ou transação atômica sem evidência
da rota nativa. Só uma geração obtida com consistência comprovada autoriza
mutação. Resultado parcial ou incerto bloqueia novas mutações até confirmação
de quiescência e reconciliação por leitura. Uma leitura enquanto o callback
ainda pode executar não libera o bloqueio; se a build não permite reconciliar
com segurança, a capacidade permanece bloqueada nessa época. Nunca se repete
automaticamente a concessão.

## Invocação SLI

`memory_debug_santamonica_runtime_invoke` chama somente função SLI marcada
`invocable`, por `function_id` opaco publicado (nome é descritivo),
`idempotency_key`, `authorized: true` e argumentos JSON validados/marshaleados
pelo RTTI. Intervalo, enum, array, nome, quantidade e ownership são checados.
Ponteiros/referências usam handles opacos da mesma sessão; JSON não transporta
endereços crus. A operação é serializada com gameplay e executada no
main-thread dispatcher. O contrato inclui `session_id` e `runtime_id`;
precondições e gerações dependem dos efeitos declarados no perfil. ABI,
ownership de argumentos/retorno e destruição são explícitos; varargs, callbacks
cliente, ponteiros crus e overload ambíguo ficam indisponíveis.

## Operações mutáveis e recuperação

Lua, grant/removal e invoke usam registro próprio de operações na aplicação.
Não são jobs de scan: a Spec 0008 exclui execução/escrita no alvo, e seus
estados de cancelamento não representam commit. Reutilizar utilitários de
limites/relógio é permitido, sem encaminhar mutações ao pool de scans.

| Tool proposta | Contrato |
|---|---|
| `memory_debug_santamonica_runtime_operation_status` | consulta por `session_id` + `operation_id`, ou por `session_id` + `runtime_id` + `idempotency_key` se a resposta inicial se perdeu; retorna estado e resultado limitado |
| `memory_debug_santamonica_runtime_operation_cancel` | recebe sessão e operação; cancela a fila ou solicita parada cooperativa; nunca promete desfazer efeitos |
| `memory_debug_santamonica_runtime_operation_release` | recebe sessão e operação; libera resultado terminal, preservando tombstone de deduplicação até o TTL |

Essas tools exigem runtime e pelo menos um gate mutável no startup; consulta e
liberação não exigem nova confirmação de gameplay. Cancelamento exige
`authorized: true`. Registros sobrevivem ao release do runtime como tombstones
limitados consultáveis pela sessão; detach/expiração da sessão encerram esse
acesso. Controle de operação não ressuscita um contexto liberado.

Estados: `queued`, `running`, `commit_in_progress`, `completed`, `cancelled`,
`failed` e `outcome_unknown`. `running` permite somente preparação sem efeitos;
a transição para `commit_in_progress` ocorre antes do primeiro efeito possível.
`cancelled` garante que nenhum efeito foi iniciado; `failed` só quando a falha
sem efeitos é comprovada. Efeitos parciais conhecidos são resultado
`completed` com `effect_status: partial`; perda de observabilidade após início
produz `outcome_unknown`. `completed` não implica persistência confirmada.
Estado terminal é imutável; reconciliação posterior é evidência separada.

`idempotency_key` é obrigatório em toda mutação, incluindo `lua_execute`.
Admissão reserva atomicamente chave + digest dos argumentos normalizados antes
de enfileirar. Mesma chave/conteúdo devolve a mesma operação; conteúdo diferente
retorna `idempotency_conflict`. A bridge também deduplica por época/operação
antes de executar; reconexão não causa reenvio cego. Cancelar o request MCP
suprime sua resposta conforme o transporte, mas não desfaz operação admitida;
o cliente consulta pela chave. Timeout de espera não é falha da transação.

Retenção e `dedup_expires_at` são publicados; enquanto a chave é válida,
liberar o resultado não autoriza executá-la de novo. Após TTL, restart do
servidor/bridge ou perda de sessão não há garantia de deduplicação durável:
reconcilie inventário/save antes de nova mutação. Não se promete exactly-once
entre crashes. Se não houver capacidade de reter o tombstone, rejeitar nova
admissão com `resource_limit`, sem remover proteção ainda válida. Operações
ativas não expiram; `dedup_expires_at` permanece nulo até o término. Expirar
um registro terminal incerto não remove o bloqueio de mutação por processo,
que sobrevive ao release do runtime até comprovar quiescência/reconciliação.

## Lifecycle, concorrência e logs

`memory_debug_santamonica_runtime_release` invalida o contexto; detach,
expiração e identidade do processo alterada fazem o mesmo. Há uma fila limitada
e no máximo uma operação engine/Lua ativa por processo. Release fecha admissão,
descarta tarefas ainda não iniciadas e solicita parada cooperativa; trabalho
com efeitos iniciados conserva seus recursos até conclusão ou limpeza segura.
Perda do canal, alvo encerrado ou deadline após efeitos gera resultado incerto,
não sucesso nem rollback implícito. Nenhum mutex da sessão permanece durante
engine/Lua e não há threads destacadas.

Servidor não espera indefinidamente por callback do alvo: encerra seu I/O com
deadline e libera recursos locais sem descarregar a bridge viva. No alvo,
heartbeat expirado fecha admissão e cancela fila; hooks/estado necessários a
callback ativo permanecem residentes até retorno ou fim do processo. Não há
unload nem encerramento forçado do jogo como consequência de timeout/release.
Inicialização de IPC, hooks e waits ocorre fora de `DllMain`/loader lock.

### Orçamentos iniciais propostos

Valores são tetos iniciais a validar no alvo controlado; o cliente só pode
reduzi-los. Ajustes exigem evidência de latência, memória e impacto no tick.

| Recurso | Teto inicial |
|---|---:|
| Frame IPC / página serializada | 1 MiB cada, abaixo do limite MCP |
| Página / string de metadados | 256 entradas / 4 KiB |
| Profundidade de referências / nós visitados por descoberta | 32 / 100.000 |
| Snapshots retidos | 32 MiB por runtime / 128 MiB no servidor |
| Fila engine / operações ativas | 16 entradas / 1 por processo |
| Fonte Lua / saída por operação | 64 KiB / 64 KiB |
| Memória atribuível Lua / instruções Lua | 8 MiB / 100.000 por operação |
| Espera em fila / handshake e I/O | 5 s / 2 s |
| Trabalho cooperativo por tick | 1 ms; chamada nativa não é preemptível |
| Registros de operações, incluindo tombstones | 1.024 por sessão / 4.096 globais |
| Resultados de operação retidos | 8 MiB por sessão / 32 MiB globais |
| TTL de snapshot / resultado / deduplicação | 60 s / 5 min / 30 min após término |

Payload é contabilizado em bytes antes de cópia, parsing, enfileiramento e
serialização, inclusive estruturas aninhadas. Budget de trabalho também limita
leitura/varredura (64 MiB e 5 s totais por descoberta, incluindo no máximo
2 tentativas de estabilidade).
O limite cooperativo não garante latência máxima do frame do jogo; a etapa de
validação mede callbacks e mantém desabilitados os sem comportamento aceitável.

Erros de domínio propostos: `unsupported`, `access_denied`, `busy`,
`resource_limit`, `stale_snapshot`, `unstable_snapshot`, `invalid_argument`,
`invalid_state`, `not_found`, `idempotency_conflict` e `bridge_unavailable`.
A camada MCP mapeia-os ao envelope vigente com `reason` fechado; falhas após
admissão são consultadas como estado da operação, sem perder seu identificador.

Logs estruturados em `stderr` registram correlação, perfil, ação, resultado,
duração e tamanho de payload. Nunca incluem Lua, strings/bytes de memória,
save, paths, tokens, segredos do canal, assinaturas, RVAs ou erro nativo completo. `stdout` permanece
exclusivamente JSON-RPC/MCP.

## Não objetivos

Não há bypass de DRM, anticheat ou EDR; stealth; elevação; outro usuário;
patching de executável em disco; scan/fuzzing de assinatura fornecida pelo
cliente; ou garantia de compatibilidade entre jogos/builds Santa Monica.

## Etapas e critérios de avanço

Cada etapa é uma entrega revisável; concluir uma não habilita a próxima.
Uma prova que falha mantém a capacidade indisponível e registra o motivo.

| Etapa | Entrega | Evidência para avançar |
|---|---|---|
| 0 — Viabilidade por build | Perfil de uma build Windows x64, origem independente, mapa RTTI/SLI e hipóteses de inventário/Lua | Fingerprint reproduzível; acesso autorizado; distinção entre observado e inferido; nenhuma assinatura/layout importada da referência |
| 1 — Contratos e bridge controlada **(entregue contra alvo sintético; dispatcher pendente)** | Schema de perfil, wire protocol/bootstrap, portas, manager, policy e fake dispatcher; alvo sintético | Handshake autenticado, replay rejeitado, fila limitada, identidade/epoch e shutdown; ADR-0022 e threat model atualizados com transporte concreto |
| 2 — Reflexão somente leitura (MVP) | Discover, types/type/enums, SLI não invocável e release | Fixtures negativas; cobertura/completude honestas; tokens/gerações; build real validada sem gameplay/Lua |
| 3 — Catálogo e inventário | Semântica de definições/instâncias/save, snapshots e handles | Completude delimitada; troca de mundo/save e ABA detectados; nenhuma rota mutável habilitada |
| 4 — Gameplay tipado | Grant/removal, allowlist SLI e tools de operação | Deduplicação e resultado incerto testados; efeitos nativos validados e persistência comprovada em cópia de save |
| 5 — Lua e carga antecipada | Observação inicial; execução apenas após prova de isolamento/quotas/limpeza | Bootstrap não perdido, ABI real validada, tentativas de escape rejeitadas, erros/yield seguros e budget mensurado |

Gameplay não depende da entrega de Lua se houver rota SLI nativa comprovada.
Se a build só permitir gameplay via Lua, registrar essa dependência no perfil
e concluir os controles da etapa 5 antes de habilitar a etapa 4. Extração ou
substituição de scripts e suporte a outra build permanecem fora do MVP.

## Validação exigida em cada entrega

- Domínio com fixtures sintéticas próprias: RTTI/SLI válidas, ciclos, ponteiros
  inválidos, overflow, short reads, mutação/ABA e budgets exauridos.
- Contrato MCP nas duas eras suportadas: campos ausentes/desconhecidos,
  tipos/extremos, gates combinados, chamada direta com gate desligado,
  paginação cruzada e redação de erros/logs.
- Canal/alvo controlado: peer falso, replay, frame parcial/excessivo, mismatch
  de perfil/bridge, PID reutilizado, morte do alvo, reconnect e perda de ACK.
- Dispatcher com relógio controlado: cancelamento antes/depois dos efeitos,
  Lua versus SLI, duas sessões no mesmo alvo, fila cheia, release/detach,
  heartbeat expirado e shutdown durante callback bloqueado.
- Gameplay: repetição da chave antes/depois de release, conflito de payload,
  timeout após efeito, tombstone cheio/expirado, item empilhável/não empilhável,
  remoção parcial, inventário cheio, item equipado/quest e troca de save.
- Lua: fonte inválida, loop, alocação excessiva, saída excessiva, yield,
  callback nativo lento, escape por globals/loaders/debug e limpeza de erros.
- Integração manual em cópia autorizada de save: item visível/equipável quando
  aplicável, quantidades exatas, grant/removal persistidos após restart e
  ausência de corrupção observada; registrar build, cenário e resultado.
  Não depende de jogo ou save proprietário no CI nem promete ausência absoluta
  de corrupção. Sem essa prova, a capacidade mutável não é marcada suportada.
- Build C++23 com warnings altos; testes unitários/contrato no Windows e de
  domínio/fakes no Linux; ASan no MSVC, ASan/UBSan e TSan separados onde
  suportados. Registrar limitações reais da toolchain, sem chamar preset sem
  instrumentação de execução de sanitizer.
- Medir baseline e custo de descoberta, bytes retidos, p95/p99 do dispatcher
  e tempo de tick; atualizar README/API/threat model e marcar implementado
  somente o incremento aprovado pelos testes.

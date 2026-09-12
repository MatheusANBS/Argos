# Spec 0014 — Runtime Santa Monica/Kinetica: reflexão, Lua e gameplay

## Status

Proposto — nenhuma tool desta spec é anunciada por `tools/list` nesta versão.

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
| `ARGOS_MCP_ENABLE_SANTAMONICA_RUNTIME` | `0` | RTTI, SLI e catálogo |
| `ARGOS_MCP_SANTAMONICA_PROFILES` | vazio | allowlist de perfis |
| `ARGOS_MCP_ALLOW_SANTAMONICA_EARLY_LOAD` | `0` | Lua durante bootstrap |
| `ARGOS_MCP_ALLOW_SANTAMONICA_GAMEPLAY` | `0` | inventário, SLI e itens |
| `ARGOS_MCP_ALLOW_SANTAMONICA_LUA_EXECUTE` | `0` | executar fonte Lua |

Os gates são avaliados somente no startup. Gameplay e Lua também requerem
`authorized: true` em cada chamada. A resposta de discover publica as
capacidades de modding que estavam efetivamente habilitadas.

## Contexto e proveniência

`memory_debug.santamonica_runtime_discover` cria um `runtime_id` opaco após
validar nome, arquitetura, tamanho e fingerprint do módulo, versão da bridge,
assinaturas server-side e estruturas RTTI/SLI. Em `attach`, usa bridge Argos
pré-aprovada; em `early_load`, a sessão vem de início controlado antes do
runtime Lua. Um perfil divergente retorna `unsupported`.

Toda resposta derivada inclui:

```json
{
  "source": "santamonica:kinetica-runtime",
  "profile_id": "gow2018-pc-<build>",
  "process_fingerprint": "opaque",
  "bridge_version": "1",
  "snapshot_status": "stable"
}
```

O fingerprint não revela path ou bytes. A descoberta valida regiões,
alinhamento, limites, índices, strings e referências cruzadas; relê cabeçalhos
e amostras antes/depois. Snapshot instável não publica catálogo completo e
retorna códigos de invariante, nunca RVAs, padrões ou erros Win32.

## Reflexão

| Tool proposta | Contrato |
|---|---|
| `memory_debug.santamonica_runtime_types` | pagina tipos RTTI com `type_id`, nome, tamanho e base |
| `memory_debug.santamonica_runtime_type` | campos declarados/herdados, offsets, tamanho, kind, array/mapa e enum |
| `memory_debug.santamonica_runtime_enums` | pagina enum e pares nome/valor sem truncamento |
| `memory_debug.santamonica_runtime_sli_functions` | pagina funções/propriedades SLI com assinatura e `invocable` |

Tipos, nomes, strings e tabelas são limitados pela policy antes de
materialização. `page_token` é opaco e vinculado a runtime, filtro e geração.
Callback nativo não é exposto. Uma função só recebe `invocable: true` quando o
perfil conhece ABI, marshaler RTTI e ponto main-thread compatíveis.

## Lua

`memory_debug.santamonica_runtime_lua_scripts`, disponível apenas em
`early_load`, lista scripts observados com path lógico normalizado, contexto e
digest. Bytecode exige paginação e teto explícito.

`memory_debug.santamonica_runtime_lua_execute` executa fonte Lua limitada na
VM do jogo, com gates de runtime, gameplay e Lua. A bridge agenda o trabalho
no tick validado; não chama Lua na thread MCP. O resultado contém estado,
saída saneada/limitada, digest da fonte e duração. Há limites de bytes,
instruções, tempo e saída; cancelamento não deixa coroutine órfã.

Lua é uma capacidade de modding de propósito geral para a build suportada. Ela
não expõe DLL, shellcode, RVA ou chamada nativa livre.

## Itens e inventário

| Tool proposta | Contrato |
|---|---|
| `memory_debug.santamonica_runtime_items` | catálogo filtrável de definições de item com `item_id` opaco, categoria, requisitos e evidência |
| `memory_debug.santamonica_runtime_inventory` | snapshot estável com `instance_id`, `item_id`, quantidade, upgrade, flags e slot |
| `memory_debug.santamonica_runtime_grant_item` | concede `item_id` previamente listado, respeitando limites e fluxo interno |
| `memory_debug.santamonica_runtime_remove_item` | remove apenas `instance_id` previamente publicado |

`grant_item` recebe `runtime_id`, `item_id`, `quantity` e `authorized: true`.
A bridge usa a criação/concessão interna validada, para que a engine gere
identidade de instância, atualize equipamento/atributos e marque o save. A
spec proíbe construir manualmente uma struct ou escrever uma lista de itens.
O resultado devolve `operation_id` e, quando concluído, a nova `instance_id`
ou erro tipado seguro.

## Invocação SLI

`memory_debug.santamonica_runtime_invoke` chama somente função SLI marcada
`invocable`, por nome publicado e com argumentos JSON validados/marshaleados
pelo RTTI. Intervalo, enum, array, nome, quantidade e ownership são checados.
Ponteiros/referências usam handles opacos da mesma sessão; JSON não transporta
endereços crus. A operação é serializada com gameplay e executada no
main-thread dispatcher.

## Lifecycle, concorrência e logs

`memory_debug.santamonica_runtime_release` invalida o contexto; detach,
expiração e identidade do processo alterada fazem o mesmo. Há uma fila limitada
e no máximo uma operação de gameplay ativa por bridge. Cancelamento é
cooperativo entre tarefas; transação já iniciada finaliza e informa
`commit_in_progress`. Nenhum mutex da sessão permanece durante engine/Lua e
não há threads destacadas.

Logs estruturados em `stderr` registram correlação, perfil, ação, resultado,
duração e tamanho de payload. Nunca incluem Lua, strings/bytes de memória,
save, paths, assinaturas, RVAs ou erro nativo completo. `stdout` permanece
exclusivamente JSON-RPC/MCP.

## Não objetivos

Não há bypass de DRM, anticheat ou EDR; stealth; elevação; outro usuário;
patching de executável em disco; scan/fuzzing de assinatura fornecida pelo
cliente; ou garantia de compatibilidade entre jogos/builds Santa Monica.

## Aceitação antes de implementação

- fixtures de RTTI/SLI válidas, inválidas, mutáveis e oversized;
- gates, mismatch de perfil, paginação e tokens cruzados;
- erros de marshaling e source Lua inválido/excedendo limites;
- cancelamento, timeout e shutdown do dispatcher main thread;
- cópia de save controlada, com grant/removal e verificação após restart;
- tools ausentes de `tools/list` com gates desligados.

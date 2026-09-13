# Santa Monica/Kinetica — investigação e implementação incremental

## Status

Reflexão nativa somente leitura validada na instalação Steam 11168363 do operador.
Suporte de runtime definido na
[Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md).
Plano aprovado e etapa 1 fechada contra um alvo sintético: catálogo validado no
domínio, codec de snapshot ([ADR-0023](../adr/0023-santa-monica-reflection-stream.md)),
handshake autenticado ([ADR-0024](../adr/0024-santa-monica-bridge-handshake.md)),
canal local ([ADR-0025](../adr/0025-santa-monica-local-channel.md)), manager e
seis tools MCP somente leitura atrás de gate. Elas conversam com um peer
controlado que fabrica os metadados ou, com perfil do operador, com o reader
nativo da [ADR-0027](../adr/0027-santa-monica-native-reflection.md).
Na [validação da instalação Steam](gow2018-steam-11168363-evidence.md), o MCP
publicou 1.192 tipos, 7.041 campos, 482 enums, 3.791 valores e 309 funções SLI.
Cobertura permanece incompleta. Com raiz de recursos no perfil, há leitura de
inventário e escrita direta de saldo
([ADR-0028](../adr/0028-santa-monica-resources-and-execution.md)); não há bridge
que fale o protocolo dentro do jogo, dispatcher, concessão nativa, invocação de
gameplay ou execução Lua.
“Santa Monica/Kinetica” é o rótulo de trabalho deste adapter; a fonte oficial
abaixo confirma uma engine proprietária, não esse nome nem uma ABI pública.

## Evidência disponível

*God of War* (2018) foi desenvolvido em engine proprietária da Santa Monica
Studio, não em Unity ou Unreal. A apresentação oficial da GDC descreve uma
engine proprietária e um sistema de descrição de dados para o pipeline, mas
não publica um contrato de reflexão em runtime.
[GDC Vault](https://gdcvault.com/play/1026345/The-Future-of-Scene-Description)

O projeto público
[`godofwar-gameplay-tweaks`](https://github.com/Nukem9/godofwar-gameplay-tweaks)
fornece evidência independente de que a build PC examinada por ele possui:

- tabelas RTTI com declarações de tipo, campos, herança, enums, arrays,
  ponteiros e hash maps;
- registries SLI que associam nomes, callbacks e assinaturas a
  funções/propriedades da engine;
- carregamento de Lua e pontos suficientes para observar/substituir bytecode;
- assinaturas e hooks específicos da build.

A reflexão em runtime é, portanto, uma rota mais forte que scan de valores
para descobrir estruturas de inventário. Isso não prova que todas as builds
tenham os mesmos layouts: a referência fixa assinaturas e contagens de tabelas,
logo compatibilidade é obrigatoriamente por build.

## Técnica de referência e limites

A referência produz um `version.dll` no diretório do jogo, usa Detours,
ImGui e Lua. É uma estratégia de carga antecipada, útil para observar scripts
antes que a engine os carregue. Attach posterior serve para introspecção de
sessão já aberta, mas pode perder o bootstrap Lua.

O repositório declara “No license provided. TBD.” Não se copia código, scripts
ou artefatos dele para o Argos. O operador autorizou o uso de fatos de formato,
verificados em sua instalação e registrados na evidência; a implementação é
própria. Detours pode ser avaliado separadamente como biblioteca MIT:
[repositório oficial](https://github.com/microsoft/Detours).

## Estratégia por build

1. Capturar a identidade completa do executável autorizado e criar perfil
   imutável.
2. Validar assinaturas server-side até os registries RTTI/SLI; divergência
   encerra a descoberta.
3. Validar regiões, alinhamento, contagens, índices, strings e referências
   antes de publicar catálogo.
4. Exportar tipos/enums para localizar domínios de item, inventário,
   equipamento e save sem assumir offsets.
5. Usar SLI e Lua para descobrir operações de criação, concessão, remoção e
   persistência.
6. Validar cada operação contra cópia de save, inclusive após restart.

Esses passos são hipóteses a verificar na build autorizada. RTTI/SLI não
comprovam, por si, um catálogo completo de itens ou uma API de transação. Cada
perfil registra origem da evidência, fingerprint, escopo observado, lacunas e
capacidades que continuam indisponíveis. Hash em disco é combinado à validação
da imagem carregada; nomes ou padrões plausíveis não substituem identidade.

O objetivo não é inventar uma instância em memória. A operação de concessão
deve deixar a engine gerar a identidade, aplicar limites, atualizar atributos
e persistir pelo fluxo normal.

## Superfície pretendida

| Necessidade | Tools da Spec 0014 |
|---|---|
| Explorar structs/classes reais | `santamonica_runtime_types` e `_type` |
| Explorar enums | `santamonica_runtime_enums` |
| Descobrir funções internas | `santamonica_runtime_sli_functions` |
| Inspecionar scripts | `santamonica_runtime_lua_scripts` |
| Executar mod Lua | `santamonica_runtime_lua_execute` |
| Enumerar itens | `santamonica_runtime_items` |
| Ler saldos de recursos | `santamonica_runtime_resources` — **implementada** |
| Definir saldo de recurso já adquirido | `santamonica_runtime_set_resource` — **implementada**, escrita direta |
| Ler inventário de itens e equipamento | `santamonica_runtime_inventory` |
| Adicionar/remover item pela engine | `santamonica_runtime_grant_item` / `_remove_item` |
| Chamar SLI tipado | `santamonica_runtime_invoke` |
| Acompanhar/cancelar/liberar operação | `santamonica_runtime_operation_status` / `_operation_cancel` / `_operation_release` |

Operações de gameplay exigem perfil exato, bridge autorizada e gates de
startup. Leituras de inventário não dependem do gate mutável. A execução Lua
exige ambiente de capacidades restritas, ABI e quotas verificadas; sem essas
provas ela permanece indisponível. Deadline não interrompe uma chamada nativa
bloqueada com segurança.

## Ordem de entrega e limites

A Spec 0014 divide o trabalho em viabilidade por build, protocolo/bridge em
alvo controlado, reflexão somente leitura, catálogo/inventário, gameplay
tipado e finalmente Lua/carga antecipada. O MVP termina na reflexão.
A bridge da Spec 0013 só prova carregamento: ainda faltam IPC autenticado,
dispatcher, snapshots e controle de operações. Discover não injeta nem inicia
o jogo; early load começa com instalação de teste preparada pelo operador.

Mutações recebem chave de idempotência e são acompanhadas por operação.
Timeout após possível efeito não autoriza repetir grant/removal: o estado
fica incerto e exige reconciliação. Conclusão em memória não comprova save em
disco. Metadados de scripts são o escopo inicial de observação; exportação de
bytecode/fonte e substituição de scripts exigem contrato posterior.

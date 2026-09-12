# Santa Monica/Kinetica — investigação e suporte proposto

## Status

Investigação concluída; suporte de runtime proposto na
[Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md).
Não há parser nem tool implementada para esta engine nesta versão.

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

O repositório declara “No license provided. TBD.” Não copie código, layouts,
assinaturas, scripts ou artefatos dele para o Argos. A implementação deve ser
independente, observada em instalação autorizada e registrada em perfis do
operador. Detours pode ser avaliado separadamente como biblioteca MIT:
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
| Ler inventário | `santamonica_runtime_inventory` |
| Adicionar/remover item | `santamonica_runtime_grant_item` / `_remove_item` |
| Chamar SLI tipado | `santamonica_runtime_invoke` |

Operações de gameplay exigem perfil exato, bridge autorizada e gates de
startup. A execução Lua é uma capacidade poderosa de modding para o jogo
offline autorizado, não uma rota de payload nativo livre.

# ADR-0011 — Scan reverso de cadeia de ponteiros

Status: aceito

## Contexto

`scan_pointers_to` (ADR-0007) acha quem referencia um endereço, mas só um
nível. `resolve_pointer_chain` percorre uma cadeia para frente, mas exige
base e offsets já conhecidos. Falta a ponte: dado o endereço de um valor
dinâmico (heap/stack, que muda a cada execução), descobrir automaticamente
uma cadeia ESTÁVEL — ancorada em `module_base + offset` estático, que
sobrevive a reinícios porque os módulos recarregam em base relativa fixa
mesmo com ASLR. Hoje o cliente teria que alternar manualmente
`scan_pointers_to` + `memory_debug_modules`, checando à mão se cada hit caiu
num módulo e recorrendo à mão o que não caiu — muitas idas e voltas, sem
proteção contra ciclos, propenso a erro. Não é problema de performance de
varredura (o scan via leitura direta de memória já é o caminho eficiente); é
uma orquestração ausente.

## Decisão

Adicionar `memory_debug_scan_pointer_chains`, implementada em
`MemoryDebugService::scan_pointer_chains`, como uma BFS limitada por cima da
MESMA rotina interna de varredura de `scan_pointers_to`/`scan_exact` (mandato
de reuso da ADR-0007 — sem duplicar a lógica de scan). Cada nível da BFS é
uma rodada de scan reverso ("quem aponta para X"). Ao encontrar um hit dentro
do range estático de um módulo (`[base, base+size)`, verificado contra um
snapshot de `modules()` obtido uma única vez no início), emite um candidato.

Detalhe-chave do offset: como cada nível descoberto É literalmente o valor de
ponteiro achado no nível anterior (sem ajuste aritmético), todos os hops
não-finais têm offset `0`. Um candidato achado na profundidade `d`
(endereços `X_d` dentro do módulo, ..., `X_1` onde `*X_1 == target`) vira
`hop_offsets = [X_d - module.base, 0, 0, ..., 0]` (com `d-1` zeros ao final,
comprimento total `d`). Alimentar isso direto no
`resolve_pointer_chain(module.base, hop_offsets, pointer_size)` já existente
devolve exatamente `X_1` — porque cada passo de offset `0` não-final apenas
re-dereferencia o ponteiro atual, e o passo final é só soma (não
dereferencia), conforme a implementação existente. O chamador faz exatamente
mais UMA leitura de ponteiro nesse resultado para chegar ao equivalente vivo
de `target` após um reinício — uniforme para toda profundidade ≥ 1.

Se `target` já estiver dentro de um módulo, curto-circuita com zero
candidatos (não entra na BFS), em vez de inventar uma cadeia degenerada `d=0`
— isso quebraria o contrato "sempre exatamente mais um deref".

Reaproveitamento estrutural: o laço de varredura por regiões de
`scan_pattern` é extraído para uma função livre `scan_pattern_over_regions`
(recebe o snapshot de regiões como parâmetro), para que a BFS busque
`regions()`/`modules()` uma vez só e reutilize o mesmo motor por hop sem
re-buscar regiões a cada nível. `scan_pattern` vira um invólucro fino —
comportamento de `scan_exact`/`scan_pointers_to` inalterado.

Custo é limitado por um único `byte_budget` compartilhado, decrementado
cumulativamente através de todos os hops, mais dois campos com teto rígido no
`SecurityPolicy`: `max_pointer_chain_depth` (padrão 8, teto 16, env
`ARGOS_MCP_MAX_POINTER_CHAIN_DEPTH`) e `max_pointer_chain_fanout` (padrão 16,
teto 64, env `ARGOS_MCP_MAX_POINTER_CHAIN_FANOUT`).

A implementação compara cada ponteiro lido contra **toda a fronteira atual em
uma única passagem por profundidade** (`scan_pointer_frontier_over_regions`).
Assim, uma fronteira de N itens não relê o processo N vezes: o limite é
`O(max_depth)` passagens de memória, com lookup médio O(1) no conjunto de
destinos. O orçamento restante é repartido entre as profundidades ainda
possíveis, impedindo que o primeiro hop consuma sozinho todo o orçamento sem
nem tentar os seguintes. `max_fanout` limita a largura produzida por cada
passagem. A checagem `authorize_pointer_chain_scan` continua reaproveitando
`authorize_scan` internamente.

## Consequências

- extensão puramente read-only — nenhuma classe de acesso nova, sem injeção
  de código/DLL, sem hooking; apenas generalização do scan reverso existente;
- reaproveita 100% do motor de varredura e limites já revisados;
- proteção contra ciclos via conjunto `visited`;
- uma passagem multi-alvo por profundidade, em vez de uma passagem por item da
  fronteira;
- `truncated=true` cobre: orçamento esgotado, `result_limit` atingido cedo,
  fronteira/matches limitados por `max_fanout`, ou `max_depth` atingido com
  fronteira ainda não vazia;
- não adiciona nenhuma capacidade proibida.

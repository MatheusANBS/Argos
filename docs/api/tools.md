# API das tools MCP

## Convenções

- Endereços devem ser strings hexadecimais, por exemplo `0x7FF612340000`.
- Bytes entram e saem em hexadecimal sem prefixo obrigatório.
- Toda resposta de tool contém `ok` e `data` ou `error`.
- Erros de execução são retornados com `isError: true`, sem expor mensagens nativas sensíveis.
- Tool inexistente ou requisição MCP estruturalmente inválida retorna erro JSON-RPC `-32602`; cada definição anuncia `outputSchema` para o envelope estruturado `ok`/`data`/`error`.

## Fluxo recomendado

1. `memory_debug_process_list`
2. `memory_debug_attach`
3. `memory_debug_address_space_summary` para dimensionar o alvo antes de varrer
4. `memory_debug_regions` (com filtro) e/ou `memory_debug_modules`
5. `memory_debug_read`, `read_typed`, `read_batch`, `scan_exact`, `scan_pointer_chains` ou `resolve_pointer_chain`
6. `memory_debug_inspect_address` para classificar um endereço encontrado
7. `memory_debug_detach`

## Operações básicas

- `memory_debug_process_list`: lista processos com filtro/limite e informa se pertencem ao mesmo usuário;
- `memory_debug_sessions`: lista apenas as sessões abertas por esta instância;
- `memory_debug_modules`: lista módulos/mapeamentos carregados da sessão;
- `memory_debug_read`: lê um intervalo limitado e devolve bytes hexadecimais;
- `memory_debug_read_batch`: preserva a ordem de até 256 itens e coalesce intervalos adjacentes ou sobrepostos; em falha/short-read de uma run, repete os itens individualmente para preservar a semântica;
- `memory_debug_read_typed`: decodifica inteiros, floats e UTF-8 little-endian;
- `memory_debug_resolve_pointer_chain`: soma cada offset não final antes de dereferenciar um ponteiro de 32/64 bits; o último offset produz o endereço final.

## Exemplo de attach

```json
{
  "name": "memory_debug_attach",
  "arguments": {
    "pid": 12345,
    "access": "read_only",
    "authorized": true
  }
}
```

## Dimensionar o espaço de endereçamento

`memory_debug_address_space_summary` devolve totais e contagens agregadas por classe de região numa resposta pequena e de tamanho constante, qualquer que seja o alvo. Use antes de qualquer scan para saber quanto há para varrer e escolher `byte_budget` com base em fato, não em palpite.

`scannable_bytes` conta apenas regiões legíveis; `scannable_writable_bytes` conta legíveis **e** graváveis — são exatamente os dois totais que um scan com e sem `writable_only` percorreria.

```json
{"name": "memory_debug_address_space_summary", "arguments": {"session_id": "..."}}
```

```json
{
  "ok": true,
  "data": {
    "region_count": 25561,
    "total_bytes": 140737488355328,
    "scannable_bytes": 3484033024,
    "scannable_writable_bytes": 3484033024,
    "largest_region_bytes": 268435456,
    "lowest_address": "0x10000",
    "highest_address": "0x7FFB06494000"
  }
}
```

## Regiões com filtro e paginação

`memory_debug_regions` aceita filtros aplicados **no servidor** e paginação. Um alvo real tem dezenas de milhares de regiões, e a lista completa não é transportável — filtre ou pagine sempre.

Filtros: `readable`, `writable`, `executable`, `private` (booleanos tri-estado — ausente significa "não filtrar por este atributo", que é diferente de `false`), `start_address`/`end_address` (mantém regiões que se sobrepõem à faixa), `min_size`/`max_size` e `name_contains` (substring, case-insensitive). Paginação: `offset` e `limit` (padrão 512).

A resposta traz `total_matched` com o número total de regiões que casaram — não apenas as devolvidas — para que o cliente saiba se precisa pedir mais páginas.

```json
{"name": "memory_debug_regions", "arguments": {"session_id": "...", "writable": true, "readable": true, "min_size": 65536, "limit": 100}}
```

```json
{
  "ok": true,
  "data": {
    "regions": [{"start": "0x1AD10490000", "end": "0x1AD10500000", "readable": true, "writable": true, "executable": false, "private": true, "name": "", "size": 458752}],
    "total_matched": 1832,
    "offset": 0,
    "returned": 100,
    "truncated": true
  }
}
```

## Pointer chain

Para `base_address = B` e offsets `[o0, o1, o2]`, o servidor calcula:

```text
p1 = *(B + o0)
p2 = *(p1 + o1)
result = p2 + o2
```

`pointer_size` pode ser `"4"` ou `"8"`.

## Scan exato

`scan_exact` percorre somente regiões legíveis. `start_address` e `end_address` podem limitar a busca a um módulo, heap ou faixa conhecida. `writable_only: true` restringe a regiões também graváveis. O scan termina ao atingir `byte_budget` ou `result_limit` e marca `truncated`.

## Strings

`memory_debug_strings` extrai sequências de texto legível (`ascii` ou `utf16le`) diretamente da memória do processo, evitando que o cliente precise baixar bytes crus e decodificar localmente. Aceita os mesmos `start_address`/`end_address`/`writable_only`/`byte_budget`/`result_limit` de `scan_exact`, mais `min_length` (comprimento mínimo do run) e `encoding`. Cada string é truncada em `ARGOS_MCP_MAX_STRING_RESULT_LENGTH` caracteres. O texto extraído nunca aparece em log — só na resposta MCP.

```json
{
  "name": "memory_debug_strings",
  "arguments": {"session_id": "...", "min_length": 4, "encoding": "ascii", "byte_budget": 1048576, "result_limit": 512}
}
```

## Scan de ponteiro reverso

`memory_debug_scan_pointers_to` encontra todos os locais na memória que referenciam `target_address` como ponteiro de 4 ou 8 bytes — a operação inversa de seguir um ponteiro. É um invólucro fino sobre `scan_exact` (mesmo código de varredura, `target_address` codificado em little-endian automaticamente) e devolve o mesmo formato de resposta.

```json
{
  "name": "memory_debug_scan_pointers_to",
  "arguments": {"session_id": "...", "target_address": "0x7FF7F4082C48", "pointer_size": "8"}
}
```

## Scan de cadeia de ponteiros

`memory_debug_scan_pointer_chains` generaliza `scan_pointers_to` para múltiplos níveis: faz uma BFS reversa ("quem aponta para X", depois "quem aponta para quem aponta para X", ...) reutilizando o mesmo motor de varredura, nível a nível, até um hit cair dentro do range estático de um módulo carregado. Use quando o endereço de partida é um valor dinâmico (heap/stack, muda a cada execução) e você precisa de uma cadeia estável (`module + offset estático + hops`) que sobrevive a reinícios, em vez de repetir `scan_pointers_to` manualmente e checar módulo a módulo.

Cada candidato devolve `hop_offsets` já prontos para `resolve_pointer_chain`: todos os hops não-finais valem `0` (o passo descoberto é literalmente o ponteiro achado no nível anterior, sem ajuste aritmético) e só o primeiro elemento é um offset estático real (`X_d - module_base`).

Fluxo após reinício: chamar `memory_debug_modules` para pegar a base fresca do módulo, depois `resolve_pointer_chain(base_fresca, hop_offsets, pointer_size)` para obter o endereço fresco, e por fim mais um `read`/`read_typed` (um deref extra) para chegar ao valor vivo. Se `target_address` já está dentro de um módulo, a busca nem entra na BFS e `candidates` volta vazio (curto-circuito).

Limites dedicados: `ARGOS_MCP_MAX_POINTER_CHAIN_DEPTH` (profundidade máxima da BFS) e `ARGOS_MCP_MAX_POINTER_CHAIN_FANOUT` (largura máxima por nível), além do `byte_budget`/`result_limit` já usados por `scan_exact`. Cada nível compara os ponteiros lidos com toda a fronteira numa única passagem; aumentar o fan-out não multiplica as leituras do processo.

```json
{"name": "memory_debug_scan_pointer_chains", "arguments": {"session_id": "...", "target_address": "0x1F2A3B4C0010", "pointer_size": "8", "max_depth": 6, "max_fanout": 16}}
```

```json
{
  "ok": true,
  "data": {
    "candidates": [
      {
        "module": "Game.exe",
        "module_base": "0x7FF7F4000000",
        "hop_offsets": [81936, 0],
        "resolved_address": "0x1F2A3B4C1000"
      }
    ],
    "bytes_scanned": 13631488,
    "truncated": false
  }
}
```

## Scan incremental (first scan / next scan)

Quando não há PDB, RTTI ou valor já conhecido, `memory_debug_scan_first` e `memory_debug_scan_next` implementam a técnica clássica de scan incremental para localizar o offset de um campo dinâmico (vida, posição, score) observando como o valor muda entre leituras sucessivas.

1. `memory_debug_scan_first` varre o intervalo pedido para um `value_type` (`u8`..`u64`, `i8`..`i64`, `f32`, `f64`) usando `comparison: "unknown"` (captura todos os valores), `"exact"` (requer `value`/`value_decimal`) ou `"in_range"` (requer os dois extremos em hex ou decimal). Devolve `scan_id`, `candidate_count`, `generation: 0` e `coverage`.
2. `memory_debug_scan_next` relê **apenas os endereços já candidatos**, em runs contíguas limitadas, e filtra por `comparison`: `changed`, `unchanged`, `increased`, `decreased`, `increased_by`/`decreased_by` (requer `delta` ou `delta_decimal`) ou `exact` (requer `value` ou `value_decimal`). `in_range` não é suportado em `scan_next` — use `scan_first` para uma nova faixa.
3. `memory_debug_scan_results` pagina os endereços do mesmo snapshot imutável (`offset`/`limit`) e devolve também `total`, `returned`, `truncated`, `generation`, `value_type` e a sessão dona.
4. `memory_debug_scan_reset` zera os candidatos sem precisar de novo `attach`/`detach`.

Scan sessions morrem junto com o `detach` da sessão de depuração dona. Limites: `ARGOS_MCP_MAX_SCAN_SESSION_CANDIDATES` (candidatos retidos por scan session) e `ARGOS_MCP_MAX_SCAN_SESSIONS_PER_SESSION` (scan sessions simultâneas por sessão de depuração).

### Valor em decimal

`value`, `delta`, `range_low` e `range_high` aceitam a forma `..._decimal`, em que o servidor codifica o literal decimal em little-endian na largura de `value_type`. Em `scan_next`, o tipo vem da própria scan session. `{"value_decimal": "91293908"}` equivale a `{"value": "d4087105"}` para `i32`. Passar as duas formas do mesmo campo é erro. Estouro de largura, sinal incompatível com tipo sem sinal e literal fracionário para tipo inteiro são rejeitados em vez de truncados.

### Cobertura do scan

`scan_first` devolve `coverage` junto com a scan session. Sem isso, `candidate_count: 0` é ambíguo: pode significar "o valor não está na memória" ou "o orçamento acabou antes de chegar nele".

| Campo | Significado |
|---|---|
| `bytes_scanned` | Bytes efetivamente lidos nesta varredura |
| `bytes_eligible` | Bytes que a varredura percorreria com cobertura total, aplicando as mesmas regras de elegibilidade (`writable_only`, `start_address`/`end_address`) |
| `regions_scanned` / `regions_eligible` | Idem, em número de regiões |
| `coverage_ratio` | `bytes_scanned / bytes_eligible`, limitado a 1.0 |
| `truncated_by_budget` | O `byte_budget` foi o fator limitante |
| `truncated_by_result_limit` | O `result_limit` encheu antes do fim da varredura |
| `complete` | Varreu tudo que era elegível e não foi interrompida |

**Só trate um conjunto vazio de candidatos como conclusivo quando `complete` for `true`.** `coverage_ratio` abaixo de 1.0 com ambos os `truncated_*` em `false` indica que alguma região elegível falhou na leitura — a varredura foi parcial mesmo sem estourar limite algum.

```json
{
  "ok": true,
  "data": {
    "scan_id": "...",
    "value_type": "i32",
    "candidate_count": 0,
    "generation": 0,
    "coverage": {
      "bytes_scanned": 268435456,
      "bytes_eligible": 3484033024,
      "regions_scanned": 1204,
      "regions_eligible": 18292,
      "coverage_ratio": 0.077,
      "truncated_by_budget": true,
      "truncated_by_result_limit": false,
      "complete": false
    }
  }
}
```

```json
{"name": "memory_debug_scan_first", "arguments": {"session_id": "...", "value_type": "i32", "comparison": "unknown", "byte_budget": 33554432, "result_limit": 262144, "writable_only": true}}
{"name": "memory_debug_scan_next", "arguments": {"scan_id": "...", "comparison": "decreased"}}
{"name": "memory_debug_scan_results", "arguments": {"scan_id": "...", "offset": 0, "limit": 50}}
{"name": "memory_debug_scan_reset", "arguments": {"scan_id": "..."}}
```

## Jobs assíncronos de scan (Spec 0008)

`memory_debug_scan_start` inicia `scan_exact`, `strings`, `scan_pointers_to`, `scan_pointer_chains`, `scan_first` ou `scan_next` como um job em background que continua depois que a chamada MCP retorna. `memory_debug_job_status`, `memory_debug_job_results`, `memory_debug_job_cancel` e `memory_debug_job_release` são genéricas e servem qualquer job. Elas reusam o mesmo motor de scan e os mesmos limites das tools síncronas de mesmo nome — os resultados nunca divergem entre os dois caminhos. No máximo um scan longo (síncrono ou assíncrono) roda por sessão de depuração por vez; uma segunda tentativa síncrona enquanto um job está `running` recebe `invalid_state`/`analysis_job_active`.

1. `memory_debug_scan_start` valida `operation` e converte `request` no mesmo tipo C++ usado pela tool síncrona correspondente antes de qualquer I/O; `execution.byte_budget`/`execution.deadline_ms` só podem reduzir os limites do servidor, nunca ampliá-los. Responde imediatamente com o job em `queued` (ou já `running`/`completed` para alvos pequenos).
2. `memory_debug_job_status` faz polling do estado, do progresso monotônico (`sequence`, bytes/regiões varridas, matches) e, uma vez terminal, do bloco `termination` com `stop_reason`, `coverage_complete`, `results_complete` e `truncated`.
3. `memory_debug_job_results` pagina o resultado imutável (`offset`/`limit`) uma vez que o job seja terminal; antes disso responde `invalid_state`/`job_not_terminal`, e depois do TTL de retenção responde `invalid_state`/`results_expired`.
4. `memory_debug_job_cancel` pede parada cooperativa; em `queued` o job termina imediatamente, em `running` fica `cancel_requested: true` até o próximo checkpoint. Chamar de novo após terminal é idempotente.
5. `memory_debug_job_release` remove um job terminal e seus resultados retidos; `queued`/`running` respondem `invalid_state`/`job_not_terminal` — cancele primeiro.

`ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES` limita, de forma agregada sobre todos os jobs retidos ao mesmo tempo (não por job), quantos bytes de resultado o servidor mantém em memória. Um job pode terminar com o scan totalmente coberto (`coverage_complete: true`) e ainda assim não conseguir reter todos os matches encontrados porque outros jobs já ocupam a maior parte do orçamento agregado; nesse caso o servidor mantém o maior prefixo de resultados que couber e sinaliza a perda como qualquer outra truncagem: `truncated: true`, `results_complete: false` e `"retained_bytes_budget"` em `truncation_reasons`. `job_release`, a expiração do TTL de resultados e `detach_session` devolvem os bytes liberados ao orçamento agregado, disponíveis para os próximos jobs.

```json
{
  "name": "memory_debug_scan_start",
  "arguments": {
    "session_id": "...",
    "operation": "scan_exact",
    "request": {"pattern_hex": "d4087105", "writable_only": true, "result_limit": 4096},
    "execution": {"byte_budget": 4294967296, "deadline_ms": 300000}
  }
}
```

```json
{"ok": true, "data": {"job_id": "...", "job_kind": "scan", "operation": "scan_exact", "state": "queued", "cancel_requested": false, "progress": {"sequence": 0, "bytes_scanned": 0, "bytes_eligible": 0, "bytes_skipped": 0, "regions_scanned": 0, "regions_eligible": 0, "regions_skipped": 0, "matches_found": 0, "matches_retained": 0, "coverage_ratio": 1.0}, "results_available": false, "results_expired": false, "termination": null}}
```

```json
{"name": "memory_debug_job_status", "arguments": {"session_id": "...", "job_id": "..."}}
{"name": "memory_debug_job_results", "arguments": {"session_id": "...", "job_id": "...", "offset": 0, "limit": 100}}
{"name": "memory_debug_job_cancel", "arguments": {"session_id": "...", "job_id": "..."}}
{"name": "memory_debug_job_release", "arguments": {"session_id": "...", "job_id": "..."}}
```

Um `job_status` terminal e truncado:

```json
{
  "ok": true,
  "data": {
    "job_id": "...", "job_kind": "scan", "operation": "scan_exact", "state": "completed", "cancel_requested": false,
    "progress": {"sequence": 104, "bytes_scanned": 2147483648, "bytes_eligible": 3484033024, "bytes_skipped": 0,
      "regions_scanned": 11021, "regions_eligible": 18292, "regions_skipped": 0, "matches_found": 4096,
      "matches_retained": 4096, "coverage_ratio": 0.6164},
    "results_available": true, "results_expired": false,
    "termination": {"stop_reason": "result_limit", "coverage_complete": false, "results_complete": false,
      "complete": false, "truncated": true, "truncation_reasons": ["result_limit"], "read_error_count": 0,
      "next_start_address": "0x1FE49001234", "resume_token": null}
  }
}
```

`job_results` para o mesmo job (o payload de `items` é discriminado por `operation` e usa o mesmo shape da tool síncrona correspondente):

```json
{
  "ok": true,
  "data": {
    "job_id": "...", "job_kind": "scan", "operation": "scan_exact",
    "items": [{"address": "0x1FE44726C90"}],
    "page": {"offset": 0, "returned": 1, "total": 4096, "has_more": true},
    "termination": {"stop_reason": "result_limit", "coverage_complete": false, "results_complete": false,
      "complete": false, "truncated": true, "truncation_reasons": ["result_limit"], "read_error_count": 0,
      "next_start_address": "0x1FE49001234", "resume_token": null}
  }
}
```

`scan_first`/`scan_next` acrescentam `scan_id`, `generation`, `candidate_count` e `draft_retained_for_resume` a `job_results`; `scan_id` só vem preenchido quando o job terminou com `range_exhausted` e cobertura/resultados completos — em qualquer resultado parcial ou cancelado, os três campos vêm `null` e `draft_retained_for_resume: false` (nesta versão, resumo de `scan_first`/`scan_next` não é suportado — o draft é descartado, não retido).

**`resume_token` não é emitido nesta versão.** `next_start_address` é diagnóstico best-effort (disponível para `scan_exact`/`scan_pointers_to` truncados por `byte_budget`/`result_limit`) e nunca deve ser usado como cursor de continuação — não há garantia de não perder nem duplicar matches na fronteira. A forma `resume_token`-only de `scan_start` é aceita pelo schema e sempre responde `unsupported`/`resume_not_supported`:

```json
{"name": "memory_debug_scan_start", "arguments": {"session_id": "...", "resume_token": "...", "execution": {"deadline_ms": 300000}}}
{"ok": false, "error": {"code": "unsupported", "message": "resume_token continuation is not implemented in this version", "reason": "resume_not_supported"}}
```

## PDB — enumeração de tipos

`memory_debug_pdb_list_types` lista os tipos (`class`/`struct`/`enum`/`union`) presentes no PDB de um módulo já carregado na sessão, para descobrir nomes antes de chamar `memory_debug_pdb_type`. Aceita `name_filter` (substring, case-insensitive) e `kind_filter` opcionais, além de `max_symbols`. Mesma regra de proveniência de `pdb_type`: `confidence: high` só quando o PDB corresponde ao binário carregado; nenhum caminho de PDB arbitrário é aceito do cliente.

```json
{"name": "memory_debug_pdb_list_types", "arguments": {"session_id": "...", "module": "Game.exe", "kind_filter": "struct"}}
```

## Início gerenciado de processo

`memory_debug_launch` inicia um executável escolhido pelo operador e captura seu `stdout`/`stderr`, útil quando o próprio alvo imprime informação de diagnóstico ao iniciar (como o binário de teste `argos_debug_target_game.exe`). **Desligado por padrão** — requer o servidor iniciado com `ARGOS_MCP_ALLOW_LAUNCH=1`, path absoluto do executável e `authorized: true`. Não substitui `attach`: não serve para anexar a processos de terceiros já em execução.

`memory_debug_read_output` faz polling do buffer de saída capturado (`since_cursor`/`max_bytes`, modelo request/response, sem streaming). `memory_debug_detach` aceita `terminate: true` para encerrar o processo — só permitido em sessões criadas por `launch` (`owned`); uma sessão de `attach` nunca pode ser encerrada pelo MCP.

```json
{"name": "memory_debug_launch", "arguments": {"executable": "C:\\...\\argos_debug_target_game.exe", "authorized": true}}
{"name": "memory_debug_read_output", "arguments": {"session_id": "...", "since_cursor": 0, "max_bytes": 65536}}
{"name": "memory_debug_detach", "arguments": {"session_id": "...", "terminate": true}}
```

`argv` é sempre um vetor de strings, nunca uma linha de comando montada por concatenação — `CreateProcessW` é chamado diretamente, sem `cmd.exe`/shell intermediário. Ver `docs/threat-model/runtime-memory-debug.md` para os controles completos (allowlist de diretório, limite de processos simultâneos, limite de buffer).

## Escrita

`memory_debug_write` vem habilitada no startup (`ARGOS_MCP_ALLOW_WRITE=0`
desliga). Requisitos cumulativos que permanecem:

1. attach com `access: "read_write"` e `authorized: true`;
2. chamada com `confirmation: "AUTHORIZED_DEBUG_WRITE"`;
3. tamanho dentro de `ARGOS_MCP_MAX_WRITE_BYTES`;
4. mesmo usuário, salvo configuração explícita em contrário.

## Tipo via PDB

`memory_debug_pdb_type` recebe `session_id`, `module`, `type` e opcionalmente
`max_fields`. O modulo deve ser o nome ou caminho devolvido por
`memory_debug_modules`. O resultado so e marcado como `confidence: high` quando
DbgHelp encontra o tipo no PDB correspondente ao binario carregado.

O guia oficial de decisao para Unity, Unreal e PDB esta em
[`docs/engines/unity-unreal-pdb.md`](../engines/unity-unreal-pdb.md).

## Unity IL2CPP

`memory_debug_unity_type` procura e valida `global-metadata.dat` ao lado do
modulo Unity carregado. Sem PDB, retorna nomes de tipos/campos e indices
IL2CPP, marcando offsets nativos como `-1`; com PDB correspondente, retorna o
layout nativo enriquecido.

## Unreal UHT

`memory_debug_unreal_type` consulta um tipo Unreal `A/U/F/E/I` no PDB nativo.
`memory_debug_unreal_reflection` enumera simbolos UHT `StaticClass` e
`StaticStruct` e seus RVAs relativos. Nenhuma dessas tools injeta ou executa
codigo no processo alvo.

## Inspeção de endereço

`memory_debug_inspect_address` responde, numa única chamada somente-leitura,
"o que é este endereço": região e proteções, módulo/RVA quando houver,
candidatos rankeados de início de objeto/vtable e, opcionalmente, referências a
ele dentro de um orçamento explícito.

`pointer_size` é **obrigatório** e nunca herdado do host: `"4"` ou `"8"`. Um
endereço de 64 bits com `pointer_size: "4"` é rejeitado, não truncado.

```json
{
  "name": "memory_debug_inspect_address",
  "arguments": {
    "session_id": "...",
    "address": "0x1FE44726C90",
    "pointer_size": "8",
    "lookbehind_bytes": 2048,
    "vtable_entries": 8,
    "min_executable_entries": 3,
    "max_object_candidates": 8
  }
}
```

Todo candidato é `classification: "probable"`, inclusive com
`confidence: "high"`. `field_offset` é a distância derivada entre o endereço
inspecionado e o início candidato — não um offset de propriedade confirmado.
`evidence` lista fatos observados com `observed`/`sampled`, e `provenance`
lista de onde cada fato veio, para que o ranking seja auditável em vez de um
número opaco.

Ausência é representada explicitamente: `region: null`, `module: null`,
`object_candidates: []`. Não existem sentinelas como endereço zero, RVA `-1`,
módulo `"unknown"` ou vtable fabricada. Quando a análise não pôde ser completa,
`analysis.complete` é `false` e `analysis.limitations` diz por quê
(`region_not_readable`, `lookbehind_clamped_to_region`, `lookbehind_short_read`,
`vtable_short_read`, `candidate_limit_reached`, …).

### Referências

`references` é opt-in e usa `oneOf` entre `none`, `index` e `live_scan`.
`index_id` é proibido em `live_scan` e `byte_budget` é proibido em `index` —
rejeitados, não resolvidos por precedência.

```json
{
  "references": {
    "mode": "live_scan",
    "byte_budget": 33554432,
    "result_limit": 64,
    "writable_only": false
  }
}
```

O slice devolve `budget`, `coverage`, `truncation_reasons` e, quando ainda há
espaço a varrer, um `resume_token` opaco. **Uma lista vazia de referências só é
conclusiva com `coverage.complete: true`.** A continuação usa exclusivamente o
`resume_token`, que é assinado por uma chave do processo servidor e vinculado a
sessão, alvo, largura de ponteiro e filtros: um token de outra consulta é
recusado, e `next_start_address` é apenas diagnóstico.

`mode: "index"` faz parte do contrato mas retorna `unsupported` nesta versão: o
índice persistente de ponteiros ([Spec 0010](../specs/0010-persistent-pointer-index.md))
não está implementado, e um downgrade silencioso para `live_scan` mudaria custo
e cobertura sem o cliente saber.

## Desmontador e referências de código (ADR-0029)

Duas tools **somente leitura** transformam endereços em comportamento:
decodificam bytes x86/x64 que a sessão já pode ler. Não escrevem, não instalam
hook e não executam; por isso não têm gate próprio — quem pode ler a memória
pode desmontá-la. A decodificação usa [Zydis](https://github.com/zyantific/zydis)
vendorizado, isolado atrás de uma porta de domínio.

| Tool | Contrato |
|---|---|
| `memory_debug_disassemble` | Decodifica `instruction_count` instruções a partir de `address`, com mnemônico, texto Intel, bytes e alvos resolvidos. |
| `memory_debug_find_code_references` | Varre memória executável e devolve as instruções cujo alvo resolvido cai em `[target_address, target_address+window]`. |

`pointer_size` é `"4"` ou `"8"` (padrão `"8"`), nunca herdado do host. Cada
instrução traz suas `references`: para cada branch/call relativo e operando de
memória RIP-relativo, o `target` absoluto já resolvido, o `kind` (`branch`,
`call`, `memory_read`, `memory_write`, `memory`) e `rip_relative`.

```json
{
  "name": "memory_debug_disassemble",
  "arguments": {"session_id": "...", "address": "0x14006D7370", "pointer_size": "8", "instruction_count": 32}
}
```

`find_code_references` é a tool para achar "quem lê/escreve este slot" e "quem
chama esta função". `window` (0–4096, padrão 0) amplia a correspondência para um
intervalo em torno do alvo — útil quando o slot de interesse está a alguns bytes
do início de uma estrutura. O escopo pode ser limitado por `module` (imagem de um
módulo carregado) ou por `start_address`/`end_address`; sem isso, varre toda
região executável. `byte_budget` e `result_limit` são obrigatórios e limitados
pela policy.

```json
{
  "name": "memory_debug_find_code_references",
  "arguments": {"session_id": "...", "target_address": "0x140502A4B0", "byte_budget": 67108864, "result_limit": 256}
}
```

A resposta traz `hits` (endereço, tamanho, mnemônico, texto, `target`, `kind`) e
`coverage`, com a mesma semântica do scan: **uma lista vazia só é conclusiva com
`coverage.complete: true`.** A varredura é linear: pode decodificar bytes
desalinhados em preenchimento entre funções, então um hit é evidência de
referência, não prova de limite de função. Instruções que não decodificam são
puladas por um byte, sem abortar a varredura.

## Reflexão Unreal em runtime

Desligada por padrão. As cinco tools `memory_debug_unreal_runtime_*` só entram
em `tools/list` quando `ARGOS_MCP_ENABLE_UNREAL_RUNTIME=1` **e** ao menos um
perfil embutido está em `ARGOS_MCP_UNREAL_PROFILES`. O schema de `profile_id`
oferece apenas os perfis já habilitados; uma requisição nunca liga um gate.

```json
{
  "name": "memory_debug_unreal_runtime_discover",
  "arguments": {
    "session_id": "...",
    "profile_id": "ue5-fproperty-x64",
    "mode": "explicit",
    "module": "Game-Win64-Shipping.exe",
    "roots": {
      "gu_object_array_rva": "0x01234560",
      "fname_pool_rva": "0x02345670"
    }
  }
}
```

`roots` usa `oneOf`: o par de RVAs (que exige `module`) ou o par de endereços
absolutos (válidos só na sessão corrente, `root_origin: "explicit_address"`).
Misturar as duas formas, ou enviar metade de uma, retorna `invalid_argument`.
Nos modos `profile` e `auto`, `roots` deve estar ausente. O servidor consulta
os registros de `ARGOS_MCP_UNREAL_BUILD_PROFILES`; o cliente não fornece nem
persiste fingerprints.

Antes de publicar um `runtime_id`, o servidor valida alinhamento das raízes,
região legível, coerência de `num_elements`/`max_elements`/chunks, uma amostra
limitada de slots vivos, resolução de nomes por `FNamePool` e uma classe com sua
lista de properties. `confidence: "high"` exige raízes vinculadas ao módulo e
todas as invariantes; falhas aparecem em `failed_invariants`.

Cada página de slots é lida, parseada e **relida**: o cabeçalho e um digest dos
tuples `(slot, object, serial)` precisam bater antes e depois. Comparar apenas
contagens não bastaria — um slot pode ser reciclado com a contagem intacta. Se o
alvo continuar mudando após os retries, a operação termina com `io_error` e
`unstable_snapshot`, e **nenhum catálogo parcial é publicado**.

- `unreal_runtime_classes`: pagina o catálogo; o `page_token` é opaco e
  vinculado ao contexto e ao filtro que o produziu;
- `unreal_runtime_type`: aceita `class_address` (que precisa estar no catálogo
  validado) **ou** `class_name` (`ambiguous` se houver mais de uma), e separa
  properties declaradas de herdadas, informando a classe declarante;
- `unreal_runtime_objects`: devolve apenas summaries — endereço, índice, nome,
  classe e outer. Ler o valor de um campo continua exigindo uma tool de leitura
  explícita e a policy normal da sessão;
- `unreal_runtime_release`: invalida o contexto; é idempotente para o dono
  durante uma janela curta após a liberação. `detach` e o TTL fazem o mesmo.

Toda resposta derivada carrega `source: "unreal:runtime-reflection"`,
`profile_id`, `process_fingerprint` (identificador não reversível para
comparação, não um dump de path ou de bytes), `root_origin`, `evidence`,
`failed_invariants` e `snapshot_status`. PDB e runtime permanecem fontes
distintas e comparáveis.

Limites desta entrega, explícitos por serem escopo e não defeito:

- `mode: "profile"` exige um registro server-side cujo nome, tamanho e
  assinatura bounded correspondam exatamente ao módulo carregado;
- `mode: "auto"` exige o segundo gate e tenta primeiro esses mesmos registros.
  Sem registro aplicável, retorna `unsupported` porque a descoberta multipadrão
  ([Spec 0009](../specs/0009-scan-composition-and-multi-pattern.md)) ainda não
  está implementada;
- `discover` e `objects` executam de forma síncrona e bounded. A resposta traz
  `execution: "synchronous"` e o mesmo envelope terminal
  (`result` + `termination`) do contrato assíncrono, para que a migração para
  jobs ([Spec 0008](../specs/0008-async-scan-operations.md)) seja aditiva;
- nomes vindos do alvo são sanitizados para ASCII imprimível antes de entrar no
  protocolo.

## Runtime Santa Monica/Kinetica

A [Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md)
define o suporte de runtime por build para *God of War* (2018), incluindo
reflexão RTTI, registries SLI, Lua e operações de gameplay. Nesta versão existem
a **reflexão somente leitura**, nativa ou contra um peer sintético controlado, e
o **inventário de recursos** com escrita direta de saldo
([ADR-0028](../adr/0028-santa-monica-resources-and-execution.md)). As tools de
Lua, itens, concessão nativa, invocação e operação continuam propostas e não
aparecem em `tools/list`.

Seis tools de reflexão existem, todas somente leitura e ausentes de `tools/list` a menos
que o operador habilite `ARGOS_MCP_ENABLE_SANTAMONICA_RUNTIME=1` **e** configure
uma origem: `ARGOS_MCP_SANTAMONICA_BUILD_PROFILES` (perfil de build lido
nativamente) ou `ARGOS_MCP_SANTAMONICA_PEER` (peer controlado):

| Tool | Contrato |
|---|---|
| `memory_debug_santamonica_runtime_discover` | `session_id` → `runtime_id`, identidade do snapshot, contagens e `expires_in_ms` |
| `memory_debug_santamonica_runtime_types` | pagina tipos com `type_id`, nome, tamanho e base |
| `memory_debug_santamonica_runtime_type` | um tipo com campos declarados e, com `include_inherited`, herdados |
| `memory_debug_santamonica_runtime_enums` | pagina enums e valores decimais exatos |
| `memory_debug_santamonica_runtime_sli_functions` | pagina entradas SLI descritivas |
| `memory_debug_santamonica_runtime_release` | libera o snapshot; idempotente para o dono por uma janela curta |

Há duas origens, e o servidor escolhe — nunca a requisição. Com um perfil de
build casando um módulo carregado da sessão, `discover` lê a tabela de tipos da
build real pela própria sessão de depuração, somente leitura
([ADR-0026](../adr/0026-santa-monica-native-type-reader.md)), e a resposta traz
`source: "native-type-table"`. Sem perfil, conversa com o peer controlado da
[ADR-0025](../adr/0025-santa-monica-local-channel.md), lançado pelo servidor a
partir do caminho configurado pelo operador, e a resposta traz
`source: "controlled-synthetic"` com `profile_id: "argos-controlled-peer"` para
que nenhum cliente leia isso como suporte a uma build de varejo. Em nenhum dos
dois casos o cliente fornece caminho, endpoint, endereço, RVA, DLL ou payload, e
em nenhum deles o alvo é escrito, iniciado ou injetado.

O reader nativo da [ADR-0027](../adr/0027-santa-monica-native-reflection.md)
publica herança e campos próprios, enums/valores e funções SLI das tabelas
configuradas. `coverage_complete` permanece **falso**: tabelas auxiliares de
coleções, mapas sem tamanho comprovado e propriedades SLI não estão cobertos.
`referenced_type_id: null` em ponteiros/arrays/mapas significa que não há tipo
refletido resolvido para o conteúdo; não autoriza percorrer instâncias.
Enums com o mesmo nome podem ter IDs distintos. Funções continuam não invocáveis.

O perfil server-side aceita nove campos (somente tipos), quinze ou dezesseis:

```text
build_id|profile_id|module_name|module_size|module_sha256|table_begin|table_end|names_begin|names_end|attribute_begin|attribute_end|enum_begin|enum_end|sli_begin|sli_end|resources_root
```

Tamanho em decimal; RVAs hexadecimais, fim exclusivo e pares opcionais `0|0`.
`resources_root` é o RVA de um slot de 8 bytes dentro do módulo; `0` não publica
recursos.
A família atual é `gow2018-reflection-x64-v2`, com registros TypeDecl de 80 bytes
ancorados em `+0x00`; a antiga `gow2018-typetable-x64` é recusada. Migrar apenas
o nome da família sem corrigir a origem/limites da tabela não é válido.

O `session_id` é a âncora de posse — quotas, release e limpeza no detach —, não
o processo do qual os dados vieram. Cada descoberta usa segredo, nonces e
identidade novos; um snapshot de outra execução nunca é apresentado como este.

Contratos comuns às páginas:

- `limit` é limitado por `ARGOS_MCP_MAX_SCAN_RESULTS`; `max_fields` e
  `max_values` pelos próprios tetos, e nenhum pedido os aumenta;
- `page_token` é opaco e vinculado a sessão, contexto, época do snapshot,
  filtro **e** tool: um token de outra consulta é recusado, nunca reinterpretado;
- ids de metadados são strings decimais opacas, jamais endereços, e jamais
  números JSON — um id de 64 bits não sobreviveria a um `double`;
- valores de enum trafegam como string decimal exata, inclusive
  `18446744073709551615`;
- toda entrada SLI reporta `invocable: false`: esta versão não tem caminho de
  invocação, e estar num registry não autoriza chamada.

Erros seguem a taxonomia comum: `unsupported` com o gate desligado ou sem peer,
`not_found` para contexto inexistente ou de outra sessão, `invalid_state` com
`context_expired` ou `runtime_busy`, `limit_exceeded` para orçamentos e
`invalid_argument` com `stale_snapshot` para token que não pertence à consulta.

### Inventário de recursos (ADR-0028)

Com um perfil de dezesseis campos cuja raiz não é zero, `discover` reporta
`resources_published: true` e duas tools passam a existir:

| Tool | Contrato |
|---|---|
| `memory_debug_santamonica_runtime_resources` | pagina saldos: `index`, `name` técnico, `acquired`, `quantity`, `maximum` (`null` sem teto), `unlimited`, `lams_name_id`, `display_ui` |
| `memory_debug_santamonica_runtime_set_resource` | define a quantidade de **um** recurso já adquirido, por nome técnico exato |

`santamonica_runtime_resources` aceita `name_contains` (substring ASCII sem
distinção de maiúsculas), `acquired_only`, `limit`, `page_token` e `refresh`.
O snapshot é lido da sessão na primeira consulta ou em `refresh` e fica em cache
no contexto. A resposta traz `resource_count`, `generation`,
`consistency: "validated_best_effort"`, `scope: "resources"` e
`mutation_safe: false`. `refresh` junto com `page_token` é recusado
(`refresh_restarts_pagination`), e um token de geração anterior é
`stale_snapshot`. Quantidades podem mudar logo após a leitura: é um jogo em
andamento.

`santamonica_runtime_set_resource` recebe `name`, `quantity` (`0..2147483647`) e
`confirmation: "AUTHORIZED_DEBUG_WRITE"`. É escrita direta do slot de saldo,
**não** concessão da engine: nenhum código do jogo roda e nada que reage a um
pickup é disparado. Exige escrita habilitada no servidor e sessão `read_write`,
revalida ligação e estado imediatamente antes e relê depois. Resposta:
`resource`, `previous`, `requested`, `observed`, `verified`,
`mechanism: "direct_balance_write"` e `engine_transaction: false`.

Recusas com razão estável: `session_read_only`, `resources_not_published`,
`resource_not_found`, `resource_not_acquired`, `exceeds_resource_max`,
`negative_quantity`, `quantity_overflow`, `resource_snapshot_changed` e
`runtime_process_mismatch`; a frase ausente segue `memory_debug_write`
(`unauthorized`). Falhas estruturais de leitura usam
`resource_profile_mismatch`, `resource_root_unset`, `resource_store_unset`,
`resource_count`, `resource_perm_mismatch`, `resource_link_mismatch`,
`resource_state_unrecognized`, `resource_state_mismatch`, `resource_name`,
`resource_read_failed` e `resource_deadline`.

Quando as demais tools forem implementadas, serão
`memory_debug_santamonica_runtime_lua_scripts`, `_lua_execute`, `_items`,
`_inventory`, `_grant_item`, `_remove_item`, `_invoke`, `_operation_status`,
`_operation_cancel` e `_operation_release`. Elas exigirão perfil exato de build
habilitado pelo operador, gates distintos e `authorized: true`; o cliente
continuará sem fornecer RVA, endereço de função, DLL ou payload nativo.

Discover apenas valida a sessão e o gate; carga por attach mantém os gates da
Spec 0013, e early load requer preparação anterior pelo operador. Inventário
não requer o gate de gameplay; Lua executável depende de prova adicional de
isolamento e quotas.

Toda mutação futura usará `idempotency_key`; grant/removal também exigirão
geração esperada do inventário. Status aceitará a chave se a resposta com
`operation_id` se perder. Timeout pode produzir `outcome_unknown` e não
autoriza retry cego. Release conservará tombstone pelo prazo publicado, sem
deduplicação durável entre crashes. As tools de operação são distintas dos jobs
de scan da Spec 0008. A Spec 0014 define parâmetros, retenção, limites e
critérios de
aceitação; estes nomes não antecipam disponibilidade na API atual.

## Histórico

As tools `memory_debug_strings`, `memory_debug_scan_pointers_to`,
`memory_debug_pdb_list_types`, `memory_debug_scan_first`/`scan_next`/
`scan_results`/`scan_reset` e `memory_debug_launch`/`read_output` foram
especificadas em
[`docs/specs/0000-roadmap-introspeccao-runtime.md`](../specs/0000-roadmap-introspeccao-runtime.md)
e estão implementadas (ver seções acima). `memory_debug_scan_pointer_chains`
foi especificada em
[`docs/specs/0006-pointer-chain-scan.md`](../specs/0006-pointer-chain-scan.md)
e também está implementada.

A fase 1 de
[`docs/specs/0007-roadmap-eficiencia-agente.md`](../specs/0007-roadmap-eficiencia-agente.md)
está implementada: cobertura em `scan_first` (A3), filtro e paginação em
`memory_debug_regions` (B1), `memory_debug_address_space_summary` (B2) e valor
em decimal (F1). São extensões de contrato dentro de ADR-0009; não houve
mudança na superfície de autorização nem novo gate de ambiente.

Os itens A1/A2 do mesmo roadmap foram especificados em
[`docs/specs/0008-async-scan-operations.md`](../specs/0008-async-scan-operations.md)
(ADR [0012](../adr/0012-async-scan-progress-resumption.md)) e estão
implementados como `memory_debug_scan_start`/`job_status`/`job_results`/
`job_cancel`/`job_release` (ver "Jobs assíncronos de scan" acima), exceto a
retomada por `resume_token`, que permanece um ponto de extensão explícito e
documentado.

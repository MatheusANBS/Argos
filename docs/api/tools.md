# API das tools MCP

## Convenções

- Endereços devem ser strings hexadecimais, por exemplo `0x7FF612340000`.
- Bytes entram e saem em hexadecimal sem prefixo obrigatório.
- Toda resposta de tool contém `ok` e `data` ou `error`.
- Erros de execução são retornados com `isError: true`, sem expor mensagens nativas sensíveis.
- Tool inexistente ou requisição MCP estruturalmente inválida retorna erro JSON-RPC `-32602`; cada definição anuncia `outputSchema` para o envelope estruturado `ok`/`data`/`error`.

## Fluxo recomendado

1. `memory_debug.process_list`
2. `memory_debug.attach`
3. `memory_debug.address_space_summary` para dimensionar o alvo antes de varrer
4. `memory_debug.regions` (com filtro) e/ou `memory_debug.modules`
5. `memory_debug.read`, `read_typed`, `read_batch`, `scan_exact`, `scan_pointer_chains` ou `resolve_pointer_chain`
6. `memory_debug.detach`

## Operações básicas

- `memory_debug.process_list`: lista processos com filtro/limite e informa se pertencem ao mesmo usuário;
- `memory_debug.sessions`: lista apenas as sessões abertas por esta instância;
- `memory_debug.modules`: lista módulos/mapeamentos carregados da sessão;
- `memory_debug.read`: lê um intervalo limitado e devolve bytes hexadecimais;
- `memory_debug.read_batch`: preserva a ordem de até 256 itens e coalesce intervalos adjacentes ou sobrepostos; em falha/short-read de uma run, repete os itens individualmente para preservar a semântica;
- `memory_debug.read_typed`: decodifica inteiros, floats e UTF-8 little-endian;
- `memory_debug.resolve_pointer_chain`: soma cada offset não final antes de dereferenciar um ponteiro de 32/64 bits; o último offset produz o endereço final.

## Exemplo de attach

```json
{
  "name": "memory_debug.attach",
  "arguments": {
    "pid": 12345,
    "access": "read_only",
    "authorized": true
  }
}
```

## Dimensionar o espaço de endereçamento

`memory_debug.address_space_summary` devolve totais e contagens agregadas por classe de região numa resposta pequena e de tamanho constante, qualquer que seja o alvo. Use antes de qualquer scan para saber quanto há para varrer e escolher `byte_budget` com base em fato, não em palpite.

`scannable_bytes` conta apenas regiões legíveis; `scannable_writable_bytes` conta legíveis **e** graváveis — são exatamente os dois totais que um scan com e sem `writable_only` percorreria.

```json
{"name": "memory_debug.address_space_summary", "arguments": {"session_id": "..."}}
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

`memory_debug.regions` aceita filtros aplicados **no servidor** e paginação. Um alvo real tem dezenas de milhares de regiões, e a lista completa não é transportável — filtre ou pagine sempre.

Filtros: `readable`, `writable`, `executable`, `private` (booleanos tri-estado — ausente significa "não filtrar por este atributo", que é diferente de `false`), `start_address`/`end_address` (mantém regiões que se sobrepõem à faixa), `min_size`/`max_size` e `name_contains` (substring, case-insensitive). Paginação: `offset` e `limit` (padrão 512).

A resposta traz `total_matched` com o número total de regiões que casaram — não apenas as devolvidas — para que o cliente saiba se precisa pedir mais páginas.

```json
{"name": "memory_debug.regions", "arguments": {"session_id": "...", "writable": true, "readable": true, "min_size": 65536, "limit": 100}}
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

`memory_debug.strings` extrai sequências de texto legível (`ascii` ou `utf16le`) diretamente da memória do processo, evitando que o cliente precise baixar bytes crus e decodificar localmente. Aceita os mesmos `start_address`/`end_address`/`writable_only`/`byte_budget`/`result_limit` de `scan_exact`, mais `min_length` (comprimento mínimo do run) e `encoding`. Cada string é truncada em `ARGOS_MCP_MAX_STRING_RESULT_LENGTH` caracteres. O texto extraído nunca aparece em log — só na resposta MCP.

```json
{
  "name": "memory_debug.strings",
  "arguments": {"session_id": "...", "min_length": 4, "encoding": "ascii", "byte_budget": 1048576, "result_limit": 512}
}
```

## Scan de ponteiro reverso

`memory_debug.scan_pointers_to` encontra todos os locais na memória que referenciam `target_address` como ponteiro de 4 ou 8 bytes — a operação inversa de seguir um ponteiro. É um invólucro fino sobre `scan_exact` (mesmo código de varredura, `target_address` codificado em little-endian automaticamente) e devolve o mesmo formato de resposta.

```json
{
  "name": "memory_debug.scan_pointers_to",
  "arguments": {"session_id": "...", "target_address": "0x7FF7F4082C48", "pointer_size": "8"}
}
```

## Scan de cadeia de ponteiros

`memory_debug.scan_pointer_chains` generaliza `scan_pointers_to` para múltiplos níveis: faz uma BFS reversa ("quem aponta para X", depois "quem aponta para quem aponta para X", ...) reutilizando o mesmo motor de varredura, nível a nível, até um hit cair dentro do range estático de um módulo carregado. Use quando o endereço de partida é um valor dinâmico (heap/stack, muda a cada execução) e você precisa de uma cadeia estável (`module + offset estático + hops`) que sobrevive a reinícios, em vez de repetir `scan_pointers_to` manualmente e checar módulo a módulo.

Cada candidato devolve `hop_offsets` já prontos para `resolve_pointer_chain`: todos os hops não-finais valem `0` (o passo descoberto é literalmente o ponteiro achado no nível anterior, sem ajuste aritmético) e só o primeiro elemento é um offset estático real (`X_d - module_base`).

Fluxo após reinício: chamar `memory_debug.modules` para pegar a base fresca do módulo, depois `resolve_pointer_chain(base_fresca, hop_offsets, pointer_size)` para obter o endereço fresco, e por fim mais um `read`/`read_typed` (um deref extra) para chegar ao valor vivo. Se `target_address` já está dentro de um módulo, a busca nem entra na BFS e `candidates` volta vazio (curto-circuito).

Limites dedicados: `ARGOS_MCP_MAX_POINTER_CHAIN_DEPTH` (profundidade máxima da BFS) e `ARGOS_MCP_MAX_POINTER_CHAIN_FANOUT` (largura máxima por nível), além do `byte_budget`/`result_limit` já usados por `scan_exact`. Cada nível compara os ponteiros lidos com toda a fronteira numa única passagem; aumentar o fan-out não multiplica as leituras do processo.

```json
{"name": "memory_debug.scan_pointer_chains", "arguments": {"session_id": "...", "target_address": "0x1F2A3B4C0010", "pointer_size": "8", "max_depth": 6, "max_fanout": 16}}
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

Quando não há PDB, RTTI ou valor já conhecido, `memory_debug.scan_first` e `memory_debug.scan_next` implementam a técnica clássica de scan incremental para localizar o offset de um campo dinâmico (vida, posição, score) observando como o valor muda entre leituras sucessivas.

1. `memory_debug.scan_first` varre o intervalo pedido para um `value_type` (`u8`..`u64`, `i8`..`i64`, `f32`, `f64`) usando `comparison: "unknown"` (captura todos os valores), `"exact"` (requer `value`/`value_decimal`) ou `"in_range"` (requer os dois extremos em hex ou decimal). Devolve `scan_id`, `candidate_count`, `generation: 0` e `coverage`.
2. `memory_debug.scan_next` relê **apenas os endereços já candidatos**, em runs contíguas limitadas, e filtra por `comparison`: `changed`, `unchanged`, `increased`, `decreased`, `increased_by`/`decreased_by` (requer `delta` ou `delta_decimal`) ou `exact` (requer `value` ou `value_decimal`). `in_range` não é suportado em `scan_next` — use `scan_first` para uma nova faixa.
3. `memory_debug.scan_results` pagina os endereços do mesmo snapshot imutável (`offset`/`limit`) e devolve também `total`, `returned`, `truncated`, `generation`, `value_type` e a sessão dona.
4. `memory_debug.scan_reset` zera os candidatos sem precisar de novo `attach`/`detach`.

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
{"name": "memory_debug.scan_first", "arguments": {"session_id": "...", "value_type": "i32", "comparison": "unknown", "byte_budget": 33554432, "result_limit": 262144, "writable_only": true}}
{"name": "memory_debug.scan_next", "arguments": {"scan_id": "...", "comparison": "decreased"}}
{"name": "memory_debug.scan_results", "arguments": {"scan_id": "...", "offset": 0, "limit": 50}}
{"name": "memory_debug.scan_reset", "arguments": {"scan_id": "..."}}
```

## Jobs assíncronos de scan (Spec 0008)

`memory_debug.scan_start` inicia `scan_exact`, `strings`, `scan_pointers_to`, `scan_pointer_chains`, `scan_first` ou `scan_next` como um job em background que continua depois que a chamada MCP retorna. `memory_debug.job_status`, `memory_debug.job_results`, `memory_debug.job_cancel` e `memory_debug.job_release` são genéricas e servem qualquer job. Elas reusam o mesmo motor de scan e os mesmos limites das tools síncronas de mesmo nome — os resultados nunca divergem entre os dois caminhos. No máximo um scan longo (síncrono ou assíncrono) roda por sessão de depuração por vez; uma segunda tentativa síncrona enquanto um job está `running` recebe `invalid_state`/`analysis_job_active`.

1. `memory_debug.scan_start` valida `operation` e converte `request` no mesmo tipo C++ usado pela tool síncrona correspondente antes de qualquer I/O; `execution.byte_budget`/`execution.deadline_ms` só podem reduzir os limites do servidor, nunca ampliá-los. Responde imediatamente com o job em `queued` (ou já `running`/`completed` para alvos pequenos).
2. `memory_debug.job_status` faz polling do estado, do progresso monotônico (`sequence`, bytes/regiões varridas, matches) e, uma vez terminal, do bloco `termination` com `stop_reason`, `coverage_complete`, `results_complete` e `truncated`.
3. `memory_debug.job_results` pagina o resultado imutável (`offset`/`limit`) uma vez que o job seja terminal; antes disso responde `invalid_state`/`job_not_terminal`, e depois do TTL de retenção responde `invalid_state`/`results_expired`.
4. `memory_debug.job_cancel` pede parada cooperativa; em `queued` o job termina imediatamente, em `running` fica `cancel_requested: true` até o próximo checkpoint. Chamar de novo após terminal é idempotente.
5. `memory_debug.job_release` remove um job terminal e seus resultados retidos; `queued`/`running` respondem `invalid_state`/`job_not_terminal` — cancele primeiro.

```json
{
  "name": "memory_debug.scan_start",
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
{"name": "memory_debug.job_status", "arguments": {"session_id": "...", "job_id": "..."}}
{"name": "memory_debug.job_results", "arguments": {"session_id": "...", "job_id": "...", "offset": 0, "limit": 100}}
{"name": "memory_debug.job_cancel", "arguments": {"session_id": "...", "job_id": "..."}}
{"name": "memory_debug.job_release", "arguments": {"session_id": "...", "job_id": "..."}}
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
{"name": "memory_debug.scan_start", "arguments": {"session_id": "...", "resume_token": "...", "execution": {"deadline_ms": 300000}}}
{"ok": false, "error": {"code": "unsupported", "message": "resume_token continuation is not implemented in this version", "reason": "resume_not_supported"}}
```

## PDB — enumeração de tipos

`memory_debug.pdb_list_types` lista os tipos (`class`/`struct`/`enum`/`union`) presentes no PDB de um módulo já carregado na sessão, para descobrir nomes antes de chamar `memory_debug.pdb_type`. Aceita `name_filter` (substring, case-insensitive) e `kind_filter` opcionais, além de `max_symbols`. Mesma regra de proveniência de `pdb_type`: `confidence: high` só quando o PDB corresponde ao binário carregado; nenhum caminho de PDB arbitrário é aceito do cliente.

```json
{"name": "memory_debug.pdb_list_types", "arguments": {"session_id": "...", "module": "Game.exe", "kind_filter": "struct"}}
```

## Início gerenciado de processo

`memory_debug.launch` inicia um executável escolhido pelo operador e captura seu `stdout`/`stderr`, útil quando o próprio alvo imprime informação de diagnóstico ao iniciar (como o binário de teste `argos_debug_target_game.exe`). **Desligado por padrão** — requer o servidor iniciado com `ARGOS_MCP_ALLOW_LAUNCH=1`, path absoluto do executável e `authorized: true`. Não substitui `attach`: não serve para anexar a processos de terceiros já em execução.

`memory_debug.read_output` faz polling do buffer de saída capturado (`since_cursor`/`max_bytes`, modelo request/response, sem streaming). `memory_debug.detach` aceita `terminate: true` para encerrar o processo — só permitido em sessões criadas por `launch` (`owned`); uma sessão de `attach` nunca pode ser encerrada pelo MCP.

```json
{"name": "memory_debug.launch", "arguments": {"executable": "C:\\...\\argos_debug_target_game.exe", "authorized": true}}
{"name": "memory_debug.read_output", "arguments": {"session_id": "...", "since_cursor": 0, "max_bytes": 65536}}
{"name": "memory_debug.detach", "arguments": {"session_id": "...", "terminate": true}}
```

`argv` é sempre um vetor de strings, nunca uma linha de comando montada por concatenação — `CreateProcessW` é chamado diretamente, sem `cmd.exe`/shell intermediário. Ver `docs/threat-model/runtime-memory-debug.md` para os controles completos (allowlist de diretório, limite de processos simultâneos, limite de buffer).

## Escrita

`memory_debug.write` permanece desligada por padrão. Requisitos cumulativos:

1. servidor iniciado com `ARGOS_MCP_ALLOW_WRITE=1`;
2. attach com `access: "read_write"`;
3. chamada com `confirmation: "AUTHORIZED_DEBUG_WRITE"`;
4. tamanho dentro de `ARGOS_MCP_MAX_WRITE_BYTES`.

## Tipo via PDB

`memory_debug.pdb_type` recebe `session_id`, `module`, `type` e opcionalmente
`max_fields`. O modulo deve ser o nome ou caminho devolvido por
`memory_debug.modules`. O resultado so e marcado como `confidence: high` quando
DbgHelp encontra o tipo no PDB correspondente ao binario carregado.

O guia oficial de decisao para Unity, Unreal e PDB esta em
[`docs/engines/unity-unreal-pdb.md`](../engines/unity-unreal-pdb.md).

## Unity IL2CPP

`memory_debug.unity_type` procura e valida `global-metadata.dat` ao lado do
modulo Unity carregado. Sem PDB, retorna nomes de tipos/campos e indices
IL2CPP, marcando offsets nativos como `-1`; com PDB correspondente, retorna o
layout nativo enriquecido.

## Unreal UHT

`memory_debug.unreal_type` consulta um tipo Unreal `A/U/F/E/I` no PDB nativo.
`memory_debug.unreal_reflection` enumera simbolos UHT `StaticClass` e
`StaticStruct` e seus RVAs relativos. Nenhuma dessas tools injeta ou executa
codigo no processo alvo.

## Histórico

As tools `memory_debug.strings`, `memory_debug.scan_pointers_to`,
`memory_debug.pdb_list_types`, `memory_debug.scan_first`/`scan_next`/
`scan_results`/`scan_reset` e `memory_debug.launch`/`read_output` foram
especificadas em
[`docs/specs/0000-roadmap-introspeccao-runtime.md`](../specs/0000-roadmap-introspeccao-runtime.md)
e estão implementadas (ver seções acima). `memory_debug.scan_pointer_chains`
foi especificada em
[`docs/specs/0006-pointer-chain-scan.md`](../specs/0006-pointer-chain-scan.md)
e também está implementada.

A fase 1 de
[`docs/specs/0007-roadmap-eficiencia-agente.md`](../specs/0007-roadmap-eficiencia-agente.md)
está implementada: cobertura em `scan_first` (A3), filtro e paginação em
`memory_debug.regions` (B1), `memory_debug.address_space_summary` (B2) e valor
em decimal (F1). São extensões de contrato dentro de ADR-0009; não houve
mudança na superfície de autorização nem novo gate de ambiente.

Os itens A1/A2 do mesmo roadmap foram especificados em
[`docs/specs/0008-async-scan-operations.md`](../specs/0008-async-scan-operations.md)
(ADR [0012](../adr/0012-async-scan-progress-resumption.md)) e estão
implementados como `memory_debug.scan_start`/`job_status`/`job_results`/
`job_cancel`/`job_release` (ver "Jobs assíncronos de scan" acima), exceto a
retomada por `resume_token`, que permanece um ponto de extensão explícito e
documentado.

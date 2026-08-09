# API das tools MCP

## Convenções

- Endereços devem ser strings hexadecimais, por exemplo `0x7FF612340000`.
- Bytes entram e saem em hexadecimal sem prefixo obrigatório.
- Toda resposta de tool contém `ok` e `data` ou `error`.
- Erros de execução são retornados com `isError: true`, sem expor mensagens nativas sensíveis.

## Fluxo recomendado

1. `memory_debug.process_list`
2. `memory_debug.attach`
3. `memory_debug.regions` e/ou `memory_debug.modules`
4. `memory_debug.read`, `read_typed`, `read_batch`, `scan_exact` ou `resolve_pointer_chain`
5. `memory_debug.detach`

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

## Scan incremental (first scan / next scan)

Quando não há PDB, RTTI ou valor já conhecido, `memory_debug.scan_first` e `memory_debug.scan_next` implementam a técnica clássica de scan incremental para localizar o offset de um campo dinâmico (vida, posição, score) observando como o valor muda entre leituras sucessivas.

1. `memory_debug.scan_first` varre o intervalo pedido para um `value_type` (`u8`..`u64`, `i8`..`i64`, `f32`, `f64`) usando `comparison: "unknown"` (captura todos os valores), `"exact"` (requer `value` em hex) ou `"in_range"` (requer `range_low`/`range_high` em hex). Devolve `scan_id`, `candidate_count` e `generation: 0`.
2. `memory_debug.scan_next` relê **apenas os endereços já candidatos** (nunca o intervalo inteiro de novo) e filtra por `comparison`: `changed`, `unchanged`, `increased`, `decreased`, `increased_by`/`decreased_by` (requer `delta` em hex) ou `exact` (requer `value`). `in_range` não é suportado em `scan_next` — a chamada não tem parâmetro de faixa; use `scan_first` novamente se precisar de uma nova faixa.
3. `memory_debug.scan_results` pagina os endereços candidatos atuais (`offset`/`limit`).
4. `memory_debug.scan_reset` zera os candidatos sem precisar de novo `attach`/`detach`.

Scan sessions morrem junto com o `detach` da sessão de depuração dona. Limites: `ARGOS_MCP_MAX_SCAN_SESSION_CANDIDATES` (candidatos retidos por scan session) e `ARGOS_MCP_MAX_SCAN_SESSIONS_PER_SESSION` (scan sessions simultâneas por sessão de depuração).

```json
{"name": "memory_debug.scan_first", "arguments": {"session_id": "...", "value_type": "i32", "comparison": "unknown", "byte_budget": 33554432, "result_limit": 262144, "writable_only": true}}
{"name": "memory_debug.scan_next", "arguments": {"scan_id": "...", "comparison": "decreased"}}
{"name": "memory_debug.scan_results", "arguments": {"scan_id": "...", "offset": 0, "limit": 50}}
{"name": "memory_debug.scan_reset", "arguments": {"scan_id": "..."}}
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

Requisitos cumulativos:

1. servidor iniciado com `ARGOS_MCP_ALLOW_WRITE=1`;
2. attach com `access: "read_write"`;
3. chamada com `confirmation: "AUTHORIZED_DEBUG_WRITE"`;
4. tamanho dentro de `ARGOS_MCP_MAX_WRITE_BYTES`.

## Histórico

As tools `memory_debug.strings`, `memory_debug.scan_pointers_to`,
`memory_debug.pdb_list_types`, `memory_debug.scan_first`/`scan_next`/
`scan_results`/`scan_reset` e `memory_debug.launch`/`read_output` foram
especificadas em
[`docs/specs/0000-roadmap-introspeccao-runtime.md`](../specs/0000-roadmap-introspeccao-runtime.md)
e estão implementadas (ver seções acima).

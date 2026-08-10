# Spec 0006 — `memory_debug.scan_pointer_chains`

Status: aceito · ADR: [0011](../adr/0011-reverse-pointer-chain-scan.md)

## Objetivo

Dado o endereço de um valor dinâmico, achar cadeias de ponteiros estáveis
(`módulo + offset estático + hops`) que sobrevivem a reinícios —
automatizando a busca reversa multi-nível que hoje seria manual (alternar
`scan_pointers_to` + `memory_debug.modules` à mão, sem proteção contra
ciclos).

## Contrato de domínio

```cpp
struct PointerChainCandidate {
    std::string module_name;
    domain::Address module_base{};
    std::vector<std::int64_t> hop_offsets;   // pronto para resolve_pointer_chain
    domain::Address resolved_address{};      // resultado de resolve_pointer_chain no momento do scan
};

struct PointerChainScanResult {
    std::vector<PointerChainCandidate> candidates;
    std::size_t bytes_scanned{};
    bool truncated{false};
};

[[nodiscard]] domain::Result<PointerChainScanResult> scan_pointer_chains(
    const domain::SessionId& id,
    domain::Address target,
    std::size_t pointer_size,            // 4 ou 8
    std::size_t max_depth,
    std::size_t max_fanout,
    std::size_t byte_budget,
    std::size_t result_limit,
    bool writable_only,
    std::optional<domain::Address> start_address = std::nullopt,
    std::optional<domain::Address> end_address = std::nullopt,
    std::stop_token cancellation = {}
) const;
```

Implementação: faz BFS reversa reutilizando a rotina interna de varredura
(extraída para `scan_pattern_over_regions`, que recebe o snapshot de regiões
como parâmetro); constrói `hop_offsets = [X_d - module.base, 0, ..., 0]`; e
preenche `resolved_address` chamando o próprio `resolve_pointer_chain` sobre o
candidato. O candidato individual é pulado (soft-skip) se essa resolução
falhar, em vez de falhar a chamada toda — espelhando o padrão por-item de
`read_batch`. Nenhuma porta de domínio nova.

Erros: `invalid_argument` (`pointer_size` fora de `{4, 8}`, `target == 0`,
`end_address <= start_address`); `limit_exceeded` (`byte_budget` /
`result_limit` / `max_depth` / `max_fanout` fora dos limites configurados,
via `authorize_pointer_chain_scan`); `cancelled`; mais os demais códigos
herdados da varredura.

## Contrato de API (MCP)

Tool: `memory_debug.scan_pointer_chains`

```json
{
  "session_id": "…",
  "target_address": "0x1F2A3B4C0010",
  "pointer_size": "8",
  "max_depth": 6,
  "max_fanout": 16,
  "byte_budget": 33554432,
  "result_limit": 32,
  "writable_only": false
}
```

Só `session_id` e `target_address` são obrigatórios; os demais têm defaults
vindos da policy.

Resposta:

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

Fluxo após reinício: chamar `memory_debug.modules` para a base fresca do
módulo, `resolve_pointer_chain(base_fresca, hop_offsets, pointer_size)` para o
endereço fresco de `X_1`, depois `read`/`read_typed` com mais um deref para o
valor vivo. Se `target` já está num módulo, `candidates` volta vazio
(curto-circuito `d=0`).

## Segurança

Mesmos limites de `authorize_scan` (reaproveitados) mais os dois tetos novos
`max_pointer_chain_depth` / `max_pointer_chain_fanout` (envs
`ARGOS_MCP_MAX_POINTER_CHAIN_DEPTH` / `ARGOS_MCP_MAX_POINTER_CHAIN_FANOUT`).
Cada profundidade faz uma única passagem multi-alvo, comparando o ponteiro
decodificado com um conjunto da fronteira; portanto o custo de I/O é limitado
a `O(max_depth)` passagens, não `O(max_depth × max_fanout)`. Read-only, sem
nova classe de risco; `visited` previne ciclos.

## Observabilidade

O código atual só emite o log genérico de `tool_call` em `invoke()`; não
existe log por-tool de matches/bytes — o texto aspiracional de specs
anteriores nunca foi implementado. O comportamento real desta tool: nunca
loga endereços resolvidos, o conteúdo de memória apontado, nem os offsets
descobertos — apenas o registro genérico de invocação da tool.

## Plano de testes

- unitário: fixture sintética de dois hops (slot em módulo → slot em heap →
  `target`) verificando `hop_offsets` e que `resolve_pointer_chain` no
  resultado reproduz o achado de nível 1 da própria BFS; caso degenerado de
  um hop; `target` já em módulo → curto-circuito (candidatos vazios,
  `bytes_scanned == 0`, `truncated == false`); `pointer_size` inválido e
  `target == 0` → `invalid_argument`; `max_depth` / `max_fanout` zero ou
  acima do teto → `limit_exceeded`; `max_depth` raso demais → vazio +
  `truncated == true`; `byte_budget` mínimo forçando truncamento no meio da
  BFS; variante de ponteiro de 4 bytes.
- contrato: confirma que a tool aparece em `tools/list`.

## Critérios de aceite

- cadeia multi-hop resolvível byte-a-byte via `resolve_pointer_chain` com os
  `hop_offsets` retornados;
- nenhuma duplicação da lógica de varredura (reuso de
  `scan_pattern_over_regions` verificável em revisão de código);
- curto-circuito `d=0` correto;
- semântica de `truncated` conforme descrita (orçamento, `result_limit`,
  fanout, depth);
- custo limitado a `O(max_depth)` chamadas de scan, independentemente da
  largura efetiva da fronteira.

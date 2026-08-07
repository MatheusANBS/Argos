# Spec 0002 — `memory_debug.scan_pointers_to`

Status: proposto · ADR: [0007](../adr/0007-reverse-pointer-scan.md)

## Objetivo

Dado um endereço já conhecido (campo, string, objeto), encontrar todos os
locais na memória do processo que o referenciam como ponteiro — a operação
inversa de "seguir um ponteiro", útil para achar a struct dona de um campo
sem precisar codificar o endereço em hex manualmente.

## Contrato de domínio

Sem tipos novos: reaproveita `argos::application::ScanResult`
(`matches`, `bytes_scanned`, `truncated`) já usado por `scan_exact`.

```cpp
[[nodiscard]] domain::Result<ScanResult> scan_pointers_to(
    const domain::SessionId& id,
    domain::Address target,
    std::size_t pointer_size,            // "4" ou "8", mesma convenção de resolve_pointer_chain
    std::size_t byte_budget,
    std::size_t result_limit,
    bool writable_only,
    std::optional<domain::Address> start_address = std::nullopt,
    std::optional<domain::Address> end_address = std::nullopt,
    std::stop_token cancellation = {}
) const;
```

Implementação: codifica `target` em `pointer_size` bytes little-endian e
delega para a mesma rotina interna de varredura usada por `scan_exact`
(reuso de código, não duplicação). Nenhuma porta de domínio nova.

Erros: `invalid_argument` (`pointer_size` fora de `{4, 8}`, `target == 0`),
mesmos demais códigos de `scan_exact`.

## Contrato de API (MCP)

Tool: `memory_debug.scan_pointers_to`

```json
{
  "session_id": "…",
  "target_address": "0x7FF7F4082C48",
  "pointer_size": "8",
  "byte_budget": 33554432,
  "result_limit": 50,
  "writable_only": false
}
```

Resposta: idêntica ao formato de `scan_exact`:

```json
{"ok": true, "data": {"matches": ["0x7FF7F4081CF0"], "bytes_scanned": 13631488, "truncated": false}}
```

## Segurança

Sem gate novo — mesma varredura, mesmos limites de `authorize_scan` já
auditados para `scan_exact`.

## Observabilidade

Mesmo padrão de `scan_exact`: log com contagem de matches e bytes
escaneados; nunca o conteúdo apontado.

## Plano de testes

- unitário: `target` presente uma vez / múltiplas vezes / ausente;
  `pointer_size` inválido retorna `invalid_argument`; equivalência com
  chamar `scan_exact` manualmente com o pattern hex codificado à mão (deve
  produzir exatamente os mesmos matches).
- regressão manual: reproduzir o caso desta sessão — dado o endereço do
  literal `"ARGOS-GAME-TARGET-2026!"`, `scan_pointers_to` deve encontrar o
  mesmo endereço (`0x7FF7F4081CF0`) que o `scan_exact` manual encontrou.

## Critérios de aceite

- resultado byte-a-byte idêntico ao equivalente manual com `scan_exact`;
- nenhuma duplicação da lógica de varredura (reuso interno verificável em
  revisão de código).

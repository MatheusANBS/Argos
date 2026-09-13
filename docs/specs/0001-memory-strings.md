# Spec 0001 — `memory_debug_strings`

Status: aceito · ADR: [0006](../adr/0006-memory-string-extraction.md)

## Objetivo

Extrair sequências de texto legível (ASCII ou UTF-16LE) diretamente de uma
região de memória do processo-alvo, sem o cliente precisar baixar bytes
crus e decodificar localmente.

## Não objetivos

- Não interpreta strings como identificadores de tipo/campo automaticamente
  (isso é trabalho do cliente/agente sobre o resultado).
- Não substitui `pdb_type`/`unreal_reflection` quando símbolos existem.

## Contrato de domínio

Sem porta nova. Implementado em `argos::application::MemoryDebugService`
usando `ProcessSession::read` e `regions()`/`modules()` já existentes.

```cpp
// include/argos_mcp/application/memory_debug_service.hpp
namespace argos::application {

struct StringMatch {
    domain::Address address{};
    std::string text;       // já saneado: apenas caracteres imprimíveis
    std::string encoding;   // "ascii" | "utf16le"
};

struct StringScanResult {
    std::vector<StringMatch> matches;
    std::size_t bytes_scanned{};
    bool truncated{false};
};

[[nodiscard]] domain::Result<StringScanResult> extract_strings(
    const domain::SessionId& id,
    std::size_t min_length,
    std::string_view encoding,           // "ascii" | "utf16le"
    std::size_t byte_budget,
    std::size_t result_limit,
    bool writable_only,
    std::optional<domain::Address> start_address = std::nullopt,
    std::optional<domain::Address> end_address = std::nullopt,
    std::stop_token cancellation = {}
) const;

}
```

Reaproveita `security::SecurityPolicy::authorize_scan(byte_budget, result_limit)`.
Novo campo em `SecurityPolicy`:

```cpp
std::size_t max_string_result_length{256U};  // trunca cada match individualmente
```

Erros: `invalid_argument` (encoding desconhecido, `min_length == 0`),
`invalid_state` (sessão inexistente/detach), `limit_exceeded`
(byte_budget/result_limit acima do permitido pela policy) — mesmos códigos
já usados por `scan_exact`.

## Contrato de API (MCP)

Tool: `memory_debug_strings`

```json
{
  "session_id": "…",
  "start_address": "0x7FF7F4070000",
  "end_address": "0x7FF7F4090000",
  "min_length": 4,
  "encoding": "ascii",
  "byte_budget": 1048576,
  "result_limit": 512,
  "writable_only": false
}
```

`start_address`/`end_address` são opcionais; omissos, a varredura cobre
todas as regiões legíveis da sessão (mesma semântica de `scan_exact`).

Resposta:

```json
{
  "ok": true,
  "data": {
    "matches": [
      {"address": "0x7FF7F4081D48", "text": "ARGOS DEBUG TARGET GAME", "encoding": "ascii"}
    ],
    "bytes_scanned": 131072,
    "truncated": false
  }
}
```

## Segurança

- somente leitura; nenhum gate de ambiente novo;
- texto retornado é tratado como memória do processo-alvo: nunca é
  registrado em log (`stderr`), só aparece em `data` da resposta MCP;
- `max_string_result_length` evita que uma única string patológica (ex.:
  região grande sem byte não-imprimível) estoure o payload de resposta.

## Observabilidade

Log estrutural em `stderr` contém apenas: `session_id`, intervalo
(hash/tamanho, não endereços sensíveis se a policy assim exigir), contagem
de matches e `bytes_scanned` — nunca o conteúdo de `text`.

## Plano de testes

- unitário: detecção de runs ASCII/UTF-16LE com `min_length` variando;
  truncamento por `max_string_result_length`; `byte_budget`/`result_limit`
  atingidos marcam `truncated: true`.
- contrato MCP: schema de request/response; erros de argumento inválido;
  sessão inexistente.
- regressão manual: rodar contra `argos_debug_target_game.exe` e confirmar
  que `"ARGOS DEBUG TARGET GAME"`, `"DebugPlayer"`, `"debug_arena"` e os
  rótulos de campo (`" | Speed: "`, `" | Kills: "`, `"] HP: "`) aparecem no
  resultado — o cenário real que motivou esta spec.

## Critérios de aceite

- extrai as strings do cenário de regressão acima sem exceder um único
  `read` de 64 KiB por chamada nem estourar limite de tokens do cliente;
- nenhuma alteração de comportamento em `scan_exact`/`read` existentes;
- documentação (`docs/api/tools.md`) atualizada com a nova tool.

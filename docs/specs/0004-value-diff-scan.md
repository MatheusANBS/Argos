# Spec 0004 — Scan incremental (`scan_first` / `scan_next`)

Status: proposto · ADR: [0009](../adr/0009-value-diff-scan-sessions.md)

## Objetivo

Localizar o offset de um campo dinâmico (vida, posição, score, wave) quando
não há PDB, RTTI ou nenhum outro símbolo — a técnica "first scan / next
scan": capturar um conjunto de candidatos e ir filtrando por como o valor
muda entre leituras sucessivas, sem precisar saber o valor exato a priori.

## Contrato de domínio

Novos tipos em `include/argos_mcp/domain/types.hpp`:

```cpp
class ScanSessionId final {
public:
    static std::expected<ScanSessionId, std::string> create(std::string value);
    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] bool operator==(const ScanSessionId&) const = default;
private:
    explicit ScanSessionId(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

enum class ScanValueType { u8, u16, u32, u64, i8, i16, i32, i64, f32, f64 };

enum class ScanComparison {
    exact, unknown, in_range,
    changed, unchanged, increased, decreased, increased_by, decreased_by
};

struct ScanSessionInfo {
    ScanSessionId id;
    SessionId owner;
    ScanValueType value_type{};
    std::size_t candidate_count{};
    std::uint32_t generation{};
};
```

Novo componente de aplicação `ScanSessionManager` (paralelo a
`SessionManager`, mesmo padrão de mutex + `shared_ptr`), guardando por
`ScanSessionId`: `{owner SessionId, ScanValueType, vector<pair<Address, bytes>> candidates, generation}`.

`MemoryDebugService`:

```cpp
[[nodiscard]] domain::Result<domain::ScanSessionInfo> scan_first(
    const domain::SessionId& id,
    domain::ScanValueType value_type,
    domain::ScanComparison comparison,                // exact | unknown | in_range
    std::optional<std::vector<std::byte>> value,       // exact
    std::optional<std::pair<std::vector<std::byte>, std::vector<std::byte>>> range, // in_range
    std::size_t byte_budget,
    std::size_t result_limit,
    bool writable_only,
    std::optional<domain::Address> start_address = std::nullopt,
    std::optional<domain::Address> end_address = std::nullopt,
    std::stop_token cancellation = {}
) const;

[[nodiscard]] domain::Result<domain::ScanSessionInfo> scan_next(
    const domain::ScanSessionId& scan_id,
    domain::ScanComparison comparison,                 // changed|unchanged|increased|decreased|increased_by|decreased_by|exact|in_range
    std::optional<std::vector<std::byte>> value,
    std::optional<std::vector<std::byte>> delta,       // increased_by | decreased_by
    std::stop_token cancellation = {}
) const;

[[nodiscard]] domain::Result<std::vector<domain::ScanMatch>> scan_results(
    const domain::ScanSessionId& scan_id,
    std::size_t offset,
    std::size_t limit
) const;

[[nodiscard]] domain::Result<void> scan_reset(const domain::ScanSessionId& scan_id);
```

`scan_next` relê **apenas os endereços já candidatos**, nunca o intervalo
inteiro de novo — é isso que torna a técnica eficiente em relação a repetir
`scan_first`. `scan_reset` zera os candidatos sem exigir novo
`attach`/`detach`. Scan sessions morrem junto com o `detach` da sessão de
depuração dona (`owner`).

`SecurityPolicy` ganha:

```cpp
std::size_t max_scan_session_candidates{262144U};
std::size_t max_scan_sessions_per_session{4U};
```

Erros novos reaproveitam `DebugErrorCode` existente: `limit_exceeded`
(candidatos ou sessões de scan acima do limite), `not_found`
(`ScanSessionId` inexistente), `invalid_argument` (comparação incompatível
com os parâmetros fornecidos, ex.: `exact` sem `value`).

## Contrato de API (MCP)

`memory_debug.scan_first`:

```json
{
  "session_id": "…",
  "value_type": "i32",
  "comparison": "unknown",
  "byte_budget": 33554432,
  "result_limit": 262144,
  "writable_only": true
}
```

Resposta:

```json
{"ok": true, "data": {"scan_id": "…", "value_type": "i32", "candidate_count": 51302, "generation": 0}}
```

`memory_debug.scan_next`:

```json
{"scan_id": "…", "comparison": "decreased"}
```

```json
{"ok": true, "data": {"scan_id": "…", "value_type": "i32", "candidate_count": 3, "generation": 1}}
```

`memory_debug.scan_results`:

```json
{"scan_id": "…", "offset": 0, "limit": 50}
```

```json
{"ok": true, "data": {"matches": ["0x21142FC10", "0x21142FC20", "0x21142FC30"]}}
```

`memory_debug.scan_reset`: `{"scan_id": "…"}` → `{"ok": true}`.

## Segurança

- leitura apenas; sem gate de ambiente novo;
- risco novo é consumo de memória do **processo do MCP** (não do alvo) para
  reter candidatos — mitigado por `max_scan_session_candidates` (rejeita
  crescer além do limite, marca `truncated: true`) e
  `max_scan_sessions_per_session` (evita acumular sessões de scan
  esquecidas);
- `scan_reset`/`detach` são os únicos caminhos de liberar memória de
  candidatos antes do fim do processo do MCP — documentar isso para
  clientes de longa duração.

## Observabilidade

Log por chamada: `scan_id`, `value_type`, `comparison`, `candidate_count`
antes/depois — nunca os valores lidos nem os endereços em texto livre fora
de `data`.

## Plano de testes

- unitário: `scan_first(unknown)` captura todos os valores no intervalo;
  `scan_next(decreased)` filtra corretamente contra um provider falso cujo
  segundo `read` devolve valores menores num subconjunto conhecido;
  `increased_by`/`decreased_by` com delta exato; `scan_reset` zera
  `candidate_count`; limite de candidatos e de sessões simultâneas
  rejeitando com `limit_exceeded`.
- contrato: sequência completa `scan_first` → `scan_next` × N →
  `scan_results` → `scan_reset` → `detach` libera estado.
- regressão manual: contra `argos_debug_target_game.exe`, usar o comando
  interativo `hurt` do próprio alvo (reduz HP) entre dois `scan_next` para
  convergir no offset real de `HP` dentro da struct `Player`, validando
  contra o valor impresso por `"] HP: "` no console do alvo.

## Critérios de aceite

- converge para um único candidato em cenário de regressão controlado
  (campo único conhecido variando de forma exclusiva) em até 3 rounds de
  `scan_next`;
- nenhuma sessão de scan sobrevive ao `detach` da sessão de depuração dona.

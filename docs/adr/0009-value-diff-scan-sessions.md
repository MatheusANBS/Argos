# ADR-0009 — Sessões de scan incremental (first scan / next scan)

Status: aceito

## Contexto

Sem PDB e sem RTTI para tipos definidos pelo alvo (structs simples, sem
polimorfismo, são invisíveis para varredura de RTTI), a única técnica
black-box que resta para localizar o offset de um campo dinâmico (vida,
posição, pontuação) é observar como o valor muda entre duas leituras — a
técnica clássica de "first scan / next scan" usada por ferramentas de
depuração de memória. `scan_exact` não serve para isso: exige um valor já
conhecido a priori.

## Decisão

Introduzir um subsistema de estado próprio, com identidade separada da
sessão de depuração:

```cpp
class ScanSessionId final { /* mesma forma de SessionId */ };
enum class ScanValueType { u8,u16,u32,u64,i8,i16,i32,i64,f32,f64 };
enum class ScanComparison {
    exact, unknown, in_range,
    changed, unchanged, increased, decreased, increased_by, decreased_by
};
struct ScanSessionInfo {
    ScanSessionId id;
    domain::SessionId owner;
    ScanValueType value_type{};
    std::size_t candidate_count{};
    std::uint32_t generation{};
};
```

Novas operações em `MemoryDebugService`: `scan_first` (varre o intervalo
pedido e grava o conjunto inicial de candidatos — `unknown` grava todos os
valores do tipo pedido; `exact`/`in_range` já filtram na primeira
passagem), `scan_next` (relê **apenas os endereços candidatos já
armazenados** e filtra pela comparação pedida, substituindo o valor
guardado pelo lido agora), `scan_results` (pagina o conjunto atual) e
`scan_reset` (zera os candidatos sem precisar `detach`/`attach`).

`ScanSessionManager` (aplicação) guarda os candidatos em memória do
processo do MCP, associados à `SessionId` dona; são destruídos junto com o
`detach` da sessão de depuração, igual ao ciclo de vida já definido em
ADR-0002. `SecurityPolicy` ganha `max_scan_session_candidates` e
`max_scan_sessions_per_session` para limitar o consumo de memória do
próprio servidor — `scan_first` que atingir o limite marca
`truncated: true` e para de acumular candidatos, nunca falha
silenciosamente.

## Consequências

- primeira via genérica para achar offsets de campos sem PDB/RTTI/símbolos;
- `scan_next` é eficiente porque só relê os candidatos remanescentes, não o
  intervalo inteiro de novo;
- novo vetor de custo: memória do processo do MCP (não do alvo) para reter
  candidatos — mitigado pelos dois limites novos acima;
- nenhuma escrita no processo-alvo é envolvida; a leitura continua sujeita
  às mesmas regras de `authorize_read`/`authorize_scan`;
- scan sessions não sobrevivem ao `detach` da sessão de depuração nem ao
  encerramento do processo do MCP.

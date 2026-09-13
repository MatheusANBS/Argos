# Spec 0003 — `memory_debug_pdb_list_types`

Status: aceito · ADR: [0008](../adr/0008-pdb-type-catalog-enumeration.md)

## Objetivo

Enumerar os tipos nativos disponíveis no PDB de um módulo já carregado na
sessão, para que o cliente descubra nomes de tipo (`GameState`, `Player`,
`FMyStruct`...) sem precisar já conhecê-los por outra via antes de chamar
`memory_debug_pdb_type`.

## Contrato de domínio

Extensão de `TypeMetadataProvider` (`include/argos_mcp/domain/type_metadata.hpp`):

```cpp
struct TypeSummary {
    std::string name;
    std::string kind;     // "class" | "struct" | "enum" | "union" | "unknown"
    std::uint64_t size{};
};

struct TypeCatalog {
    std::vector<TypeSummary> types;
    std::string source;      // "pdb:dbghelp"
    std::string confidence;  // mesma convenção de TypeMetadata::confidence
    bool truncated{false};
};

// novo método em TypeMetadataProvider
[[nodiscard]] virtual domain::Result<TypeCatalog> list_pdb_types(
    std::string_view module_path,
    std::string_view name_filter,   // substring, case-insensitive; "" = sem filtro
    std::string_view kind_filter,   // "" | "class" | "struct" | "enum" | "union"
    std::size_t max_symbols
) const = 0;
```

`MemoryDebugService` ganha:

```cpp
[[nodiscard]] domain::Result<domain::TypeCatalog> pdb_list_types(
    const domain::SessionId& id,
    std::string_view module_name,
    std::string_view name_filter,
    std::string_view kind_filter,
    std::size_t max_symbols
) const;
```

### Notas de implementação (para `PdbTypeMetadataProvider`)

Usar `SymEnumTypes`/`SymEnumTypesByName` do DbgHelp com um callback que
classifica cada símbolo via `SymGetTypeInfo(TI_GET_SYMTAG)` (`SymTagUDT` →
distinguir class/struct/union pelo `TI_GET_UDTKIND`; `SymTagEnum` → enum).
Mesmo mutex global de DbgHelp de ADR-0005; mesma regra de módulo já listado
na sessão (`modules()`), sem caminho de PDB arbitrário fornecido pelo
cliente.

`SecurityPolicy` ganha:

```cpp
std::size_t max_type_catalog_symbols{2048U};
```

## Contrato de API (MCP)

Tool: `memory_debug_pdb_list_types`

```json
{
  "session_id": "…",
  "module": "argos_debug_target_game.exe",
  "name_filter": "Game",
  "kind_filter": "struct",
  "max_symbols": 512
}
```

Resposta:

```json
{
  "ok": true,
  "data": {
    "types": [
      {"name": "GameState", "kind": "struct", "size": 96},
      {"name": "Player", "kind": "struct", "size": 48}
    ],
    "source": "pdb:dbghelp",
    "confidence": "high",
    "truncated": false
  }
}
```

Quando o módulo não tem PDB correspondente: `not_found`, mesma semântica de
`pdb_type` hoje — nunca inventa tipos.

## Segurança

Sem gate novo. Enumeração é metadado, não lê memória do processo-alvo;
custo fica limitado a `max_symbols` e ao mutex do DbgHelp já existente.

## Observabilidade

Log com `module`, contagem de tipos retornados e `truncated` — nunca os
nomes individuais (evita ruído; nomes de tipo não são segredo, mas não
agregam valor a métricas).

## Plano de testes

- unitário: provider falso com PDB de teste (pequeno, fixado em
  `tests/fixtures`) cobrindo class/struct/enum/union e filtro por nome;
  `max_symbols` truncando corretamente.
- contrato: módulo sem PDB → `not_found`; módulo não listado na sessão →
  `invalid_argument`.
- regressão manual: contra `argos_debug_target_game.exe` **com PDB gerado**
  (hoje o build Release não gera PDB — ver observação abaixo), confirmar
  que `GameState` e `Player` aparecem no catálogo.

### Observação sobre o alvo de teste atual

`build/dev/Debug/argos_debug_target_game.exe` é, na prática, um build sem
PDB ao lado do executável (o `CodeView` embutido aponta para
`build/dev/Debug/argos_debug_target_game.pdb`, que não existe no disco).
Esta spec por si só não resolve isso — é responsabilidade do build do alvo
de teste, não do MCP. Recomenda-se, como tarefa separada, garantir que o
preset `dev` gere e preserve o `.pdb` de `argos_debug_target_game` para que
os testes de regressão de `pdb_type`/`pdb_list_types` tenham um alvo real
com símbolos.

## Critérios de aceite

- catálogo retornado é subconjunto exato dos tipos que `pdb_type` consegue
  resolver individualmente (nenhuma divergência de nome entre as duas
  tools);
- `docs/api/tools.md` e `docs/engines/unity-unreal-pdb.md` atualizados.

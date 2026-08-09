# ADR-0008 — Enumeração de tipos do PDB

Status: aceito

## Contexto

`memory_debug.pdb_type` (ADR-0005) exige o nome exato do tipo nativo. Sem uma
forma de listar os tipos presentes no PDB de um módulo carregado, o cliente
só consegue usar a tool se já conhecer os nomes por outra via (código-fonte,
strings do binário, documentação) — o que contraria o objetivo de
introspecção sem código-fonte.

## Decisão

Estender `TypeMetadataProvider` (domínio) com:

```cpp
struct TypeSummary { std::string name; std::string kind; std::uint64_t size{}; };
struct TypeCatalog {
    std::vector<TypeSummary> types;
    std::string source;      // "pdb:dbghelp"
    std::string confidence;
    bool truncated{false};
};

virtual Result<TypeCatalog> list_pdb_types(
    std::string_view module_path,
    std::string_view name_filter,
    std::string_view kind_filter,   // "" | class | struct | enum | union
    std::size_t max_symbols
) const = 0;
```

`PdbTypeMetadataProvider` implementa via `SymEnumTypes`/`SymEnumTypesByName`
do DbgHelp, classificando cada símbolo com `SymGetTypeInfo(TI_GET_SYMTAG)`.
Mantém todas as regras de ADR-0005: só aceita módulo já listado na sessão
(`modules()`), roda no processo do MCP, protegido pelo mesmo mutex do
DbgHelp, e só marca `confidence: high` para entradas resolvidas no PDB
correspondente ao binário carregado. O cliente não fornece caminho de PDB
arbitrário.

## Consequências

- desbloqueia descoberta de tipos quando existe PDB, sem exigir nome prévio;
- resultado é só um índice leve (`name`, `kind`, `size`); detalhe de campos
  continua exigindo `pdb_type` por nome — evita duplicar payload grande;
- limitado por `max_symbols` (novo campo em `SecurityPolicy`,
  `max_type_catalog_symbols`), controlando custo de enumeração no processo
  do MCP;
- Unity IL2CPP e Unreal UHT não ganham enumeração nesta ADR — ficam para uma
  decisão futura, já que suas superfícies de reflexão têm fontes distintas
  (`global-metadata.dat` e símbolos `StaticClass`/`StaticStruct`).

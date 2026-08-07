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

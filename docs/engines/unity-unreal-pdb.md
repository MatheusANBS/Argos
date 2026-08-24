# Unity, Unreal e PDB: metodos de alta eficacia

Este MCP trabalha por evidencia de artefato. Ele nao precisa ler o codigo-fonte
do jogo e nao injeta DLL, thread ou codigo no processo-alvo.

## Metodo implementado: PDB

Depois de `memory_debug.attach` e `memory_debug.modules`, use:

```json
{
  "name": "memory_debug.pdb_type",
  "arguments": {
    "session_id": "...",
    "module": "Game.exe",
    "type": "GameState",
    "max_fields": 256
  }
}
```

O `module` precisa ser o nome ou caminho retornado por `memory_debug.modules`.
O MCP chama DbgHelp no proprio processo, carrega o modulo e consulta o PDB
correspondente. A resposta informa tamanho, nome, offset e tamanho de cada
campo, alem de `source: pdb:dbghelp`, `confidence: high` e `truncated`.

Fontes oficiais:

- [SymGetTypeFromName (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgettypefromname)
- [SymGetTypeInfo (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgettypeinfo)
- [DIA SDK (Microsoft)](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk?view=visualstudio)

Sem PDB correspondente, o MCP nao transforma assinatura, scan ou nome de
funcao em layout confirmado.

Quando o nome do tipo ainda nao e conhecido, `memory_debug.pdb_list_types`
enumera os tipos (`class`/`struct`/`enum`/`union`) presentes no PDB do modulo
carregado (via `SymEnumTypesW`), com filtro opcional por nome/kind. O
resultado e so um indice leve (`name`, `kind`, `size`); o layout completo de
campos continua exigindo `pdb_type` por nome. Mesmas regras de proveniencia:
so aceita modulo ja listado na sessao, roda no processo do MCP e usa o mesmo
mutex de DbgHelp.

## Unity

Unity documenta dois backends principais: Mono e IL2CPP. O backend muda quais
artefatos existem e qual informacao pode ser recuperada com confianca.

Fontes oficiais:

- [Scripting backends: Mono e IL2CPP (Unity)](https://docs.unity3d.com/ja/current/Manual/scripting-backends-intro.html)
- [Introducao ao IL2CPP (Unity)](https://docs.unity3d.com/jp/current/Manual/il2cpp-introduction.html)
- [Arquivos gerados por build Windows IL2CPP (Unity)](https://docs.unity3d.com/ja/current/Manual/WindowsPlayerIL2CPPScriptingBackend.html)
- [PreserveAttribute e stripping (Unity)](https://docs.unity3d.com/es/current/ScriptReference/Scripting.PreserveAttribute.html)

Implementacao real no MCP: `memory_debug.unity_type`.

O adapter procura `global-metadata.dat` em localizacoes de build ao lado do
modulo carregado, valida o magic/header, versao 24--31, limites das tabelas e
le type definitions e field definitions. Sem PDB nativo, nomes de campos e
`il2cpp_type_index:N` sao retornados, enquanto offsets nativos ficam
explicitamente em `-1`. Quando o PDB correspondente existe, o resultado e
enriquecido com o layout nativo do PDB e passa a `confidence: high`.

Exemplo:

```json
{
  "name": "memory_debug.unity_type",
  "arguments": {
    "session_id": "...",
    "module": "GameAssembly.dll",
    "type": "MeuJogo.Player",
    "max_fields": 256
  }
}
```

Metodo de maior eficacia sem injecao:

1. Identificar Mono ou IL2CPP a partir dos artefatos do build.
2. Para IL2CPP, conferir `GameAssembly.dll`, `SymbolMap` e, quando o build
   preservou debug, os PDB/arquivos de debug gerados.
3. Consultar `memory_debug.pdb_type` no modulo cujo PDB corresponde exatamente
   ao binario carregado.
4. Tratar metadata ausente, criptografada ou removida por stripping como
   ausencia de evidencia; o parser retorna erro, nao tenta descriptografar ou
   fazer brute force.

O formato de `global-metadata.dat` nao e apresentado pela Unity como contrato
publico estavel. Por isso o adapter tem perfis de versao e validacao estrita;
versoes futuras ou layouts obfuscados retornam `unsupported`/`parse_error`.

## Unreal Engine

Implementacao real no MCP: `memory_debug.unreal_type` e
`memory_debug.unreal_reflection`.

`memory_debug.unreal_type` consulta tipos `A/U/F/E/I` emitidos pelo build nativo
e pelo Unreal Header Tool no PDB correspondente. `memory_debug.unreal_reflection`
enumera simbolos UHT `StaticClass` e `StaticStruct`, devolvendo seus RVAs
relativos ao modulo carregado. Ambos rodam no processo MCP e nao chamam funcoes
do processo-alvo.

Fontes oficiais:

- [Reflection System in Unreal Engine](https://dev.epicgames.com/documentation/unreal-engine/reflection-system-in-unreal-engine?lang=en-US)
- [UClass API](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/UClass?lang=en-US)
- [Objects in Unreal Engine](https://dev.epicgames.com/documentation/en-us/unreal-engine/objects-in-unreal-engine?lang=en-US)
- [UProperty API](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/UProperty?lang=en-US)

`UCLASS`, `USTRUCT`, `UFUNCTION` e `UPROPERTY` sao a fonte oficial da
reflexao exposta pelo engine; campos nativos sem macros nao aparecem nessa
superficie. Para layout nativo, o PDB e a fonte mais direta e os dois tools
acima expõem a proveniencia Unreal explicitamente (`unreal:uht-pdb` e
`unreal:uht-pdb-reflection`).

O adapter nao tenta reconstruir `GUObjectArray`, `FNamePool` ou objetos vivos
por offsets heurísticos. Essa parte depende de versao/configuracao e, sem um
PDB compativel, retorna `not_found`/`unsupported`. A implementacao atual extrai
metadados e layouts comprovados; ela nao injeta codigo nem resolve objetos por
varredura cega.

Uma extensão somente-leitura por perfis de runtime está implementada conforme
[Reflexão Unreal em runtime sem PDB](../specs/0012-unreal-runtime-reflection.md)
e [ADR-0019](../adr/0019-unreal-runtime-reflection.md), desligada por padrão
atrás de gate e allowlist de perfil. Ela usa perfis explícitos, validação
estrutural, proveniência e confiança; não transforma signatures em layout
confirmado nem modifica o comportamento descrito nesta página. Quando as duas
fontes existirem, PDB e runtime permanecem separados e comparáveis.

## Nivel de confianca

| Fonte | Resultado | Confianca |
|---|---|---|
| PDB correspondente ao modulo carregado | tipo, tamanho e offsets | Alta |
| Unity `global-metadata.dat` validado | tipos, nomes e indices de campo | Media; offsets dependem de PDB |
| Unity metadata + PDB correspondente | tipo, campos e offsets nativos | Alta |
| Unreal UHT `StaticClass`/`StaticStruct` no PDB | simbolos de reflexao e RVAs | Alta |
| Unreal runtime com perfil vinculado ao modulo e todas as invariantes | classes, heranca e offsets de `FProperty` | Alta para o perfil validado; fonte separada do PDB |
| Unreal runtime com raiz apenas plausivel ou amostra parcial | candidato com `failed_invariants` | Baixa/media; nunca promovido a layout confirmado |
| Scan de bytes, assinatura ou offset heuristico | candidato | Baixa; nao e reportado como tipo confirmado |

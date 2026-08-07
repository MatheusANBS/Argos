# ADR 0005 - Metadados de tipos com proveniencia explicita

## Status

Aceito.

## Contexto

O MCP precisa extrair layouts de tipos sem ler o codigo-fonte do alvo e sem
alterar o processo. Scans de bytes e assinaturas podem encontrar candidatos,
mas nao sao uma fonte suficiente para afirmar o layout de um tipo.

Unity e Unreal tambem possuem superficies diferentes por versao e por backend.
Nao existe um formato externo unico, estavel e oficialmente documentado que
permita ao MCP reconstruir com alta confianca toda a reflexao de qualquer jogo.

## Decisao

- No Windows, o primeiro metodo de alta eficacia implementado e PDB via
  `DbgHelp`: `SymGetTypeFromName` localiza o tipo e `SymGetTypeInfo` enumera
  tamanho, campos e offsets.
- O modulo precisa estar carregado na sessao e o PDB correspondente e
  resolvido pelo proprio DbgHelp. O cliente nao fornece um caminho arbitrario.
- O resultado informa `source: pdb:dbghelp` e `confidence: high` somente quando
  o tipo foi encontrado no PDB correspondente.
- Unity: `memory_debug.unity_type` valida e le `global-metadata.dat` IL2CPP;
  quando existe PDB correspondente, combina a evidencia para obter offsets
  nativos. Versoes/layouts fora dos perfis suportados retornam erro seguro.
- Unreal: `memory_debug.unreal_type` usa os tipos UHT do PDB e
  `memory_debug.unreal_reflection` enumera simbolos `StaticClass`/`StaticStruct`.
  O MCP nao inventa offsets de `UClass`, `FProperty` ou objetos a partir de
  scans genericos.
- Nao usar DLL injection, remote thread, patching ou qualquer alteracao no
  processo-alvo. O DbgHelp roda no processo do MCP e e protegido por mutex
  porque a API oficial nao e thread-safe.

## Consequencias

O caminho PDB e reproduzivel e auditavel, mas depende de simbolos preservados.
Builds Unity IL2CPP sem PDB e Unreal sem simbolos/reflexao exportada retornam
`not_found` ou `unsupported`; isso e preferivel a reportar offsets heuristicos
como se fossem fatos.

Dependencias: `Dbghelp.lib`/`Dbghelp.dll` sao componentes do SDK/Windows no
Windows. Nao foi adicionada biblioteca de runtime de terceiros.

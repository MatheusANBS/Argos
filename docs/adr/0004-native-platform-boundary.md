# ADR-0004 — Fronteira nativa por provider

Status: aceito

## Contexto

Win32 e Linux têm modelos diferentes para enumerar processos, regiões e ler memória.

## Decisão

Isolar APIs nativas em `NativeProcessMemoryProvider` e implementações privadas de `ProcessSession`. O restante do projeto opera apenas sobre tipos do domínio.

## Consequências

- testes usam providers falsos;
- erros nativos são traduzidos para códigos seguros;
- macOS pode ser adicionado sem alterar MCP ou aplicação;
- detalhes de HANDLE, `/proc` e `iovec` não vazam para APIs públicas.

# Changelog

## Não lançado

- `memory_debug.strings`: extração de strings ASCII/UTF-16LE no servidor;
- `memory_debug.scan_pointers_to`: scan reverso de ponteiro, reaproveitando o
  mecanismo de `scan_exact`;
- `memory_debug.pdb_list_types`: enumeração de tipos do PDB via `SymEnumTypesW`;
- `memory_debug.scan_first`/`scan_next`/`scan_results`/`scan_reset`: scan
  incremental (first scan/next scan) para localizar offsets sem PDB/RTTI;
- `memory_debug.launch`/`read_output`: início gerenciado de processo com
  captura de `stdout`/`stderr`, atrás do gate `ARGOS_MCP_ALLOW_LAUNCH`
  (desligado por padrão); `memory_debug.detach` ganhou `terminate`;
- correção de segurança: `SessionManager`/`ScanSessionManager` geravam IDs
  com baixa entropia (dígitos hex recém-gerados eram zerados em vez de
  receberem padding à esquerda), colidindo na maioria das chamadas;
- correção de segurança: `memory_debug.launch` restringe explicitamente quais
  handles um processo filho herda (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`),
  evitando que o filho herde o próprio `stdout` de protocolo do MCP.

## 0.1.0 — 2026-08-05

- servidor MCP `stdio` compatível com `2025-11-25`;
- parser e serializador JSON internos;
- providers nativos para Windows e Linux;
- sessions explícitas com RAII;
- process list, attach, detach, sessions, regions e modules;
- read, read batch, typed read, exact scan e pointer chain;
- write gate desabilitado por padrão;
- cancelamento cooperativo de scans via `notifications/cancelled`;
- logs estruturados em `stderr`;
- skills C++ instaladas em `.codex/skills`;
- testes unitários, contrato MCP, presets de sanitizer e documentação de segurança.

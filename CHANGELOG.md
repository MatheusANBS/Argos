# Changelog

## Não lançado

- `memory_debug.scan_start`/`job_status`/`job_results`/`job_cancel`/
  `job_release` (Spec [0008](docs/specs/0008-async-scan-operations.md), ADR
  [0012](docs/adr/0012-async-scan-progress-resumption.md)): `scan_exact`,
  `strings`, `scan_pointers_to`, `scan_pointer_chains`, `scan_first` e
  `scan_next` agora podem rodar como job em background (`AnalysisJobManager`),
  com progresso monotônico, cancelamento cooperativo, fila e workers
  limitados, TTL de resultado/tombstone e paginação imutável, reusando o
  mesmo motor de scan das tools síncronas. No máximo um scan longo roda por
  sessão por vez (síncrono ou assíncrono). Novos limites `ARGOS_MCP_MAX_ASYNC_*`
  e `ARGOS_MCP_ASYNC_*`. Retomada por `resume_token` é um ponto de extensão
  documentado e ainda não implementado: `scan_start` responde
  `unsupported`/`resume_not_supported` para essa forma;
- compatibilidade dual-era MCP: protocolo moderno `2026-07-28` via
  `server/discover` e `_meta` por request, mantendo clientes legados
  `2025-11-25`/`2025-06-18`;
- consultas de regiões filtradas/paginadas, resumo do espaço de endereçamento,
  cobertura de `scan_first`, páginas autocontidas de `scan_results` e entrada
  numérica decimal em `scan_first`/`scan_next`;
- `scan_pointer_chains` passou de uma varredura por item da fronteira para uma
  passagem multi-alvo por profundidade;
- scan sessions usam snapshots imutáveis compartilhados, valores inline e
  leitura agrupada de candidatos contíguos em `scan_next`;
- `read_batch` coalesce intervalos adjacentes/sobrepostos e o catálogo de tools
  é construído uma vez; IPO/LTO ficou disponível como opção, mas desligado por
  padrão após regressão de 6,4% no benchmark MSVC de `tools/list`;
- framing JSON limitado a 8 MiB/128 níveis/65.536 nós, serialização iterativa,
  cancelamento MCP sem resposta tardia, `outputSchema` e erro JSON-RPC para
  tool inexistente;
- captura de processo usa buffer circular real e shutdown seguro das threads de
  pipe no Windows;
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
- skills C++ instaladas em `.skills`;
- testes unitários, contrato MCP, presets de sanitizer e documentação de segurança.

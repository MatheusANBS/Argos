# Changelog

## Não lançado

- reflexão Unreal: `mode: "profile"` agora resolve roots por perfis de build
  configurados pelo operador e `mode: "auto"` reutiliza primeiro esses perfis,
  permitindo que clientes e chats novos funcionem sem conservar RVAs no
  histórico. O fingerprint combina nome, `SizeOfImage` e assinatura bounded do
  módulo; mismatch e ambiguidade falham fechados, e todas as invariantes de
  runtime continuam obrigatórias antes de publicar um contexto;

## 0.2.0 — 2026-08-12

- build no Windows: `tools/build.ps1` importa o ambiente MSVC antes do CMake e
  compara o `msvc_deps_prefix` gravado com o que o compilador imprime,
  reconfigurando do zero quando divergem; `CMakeLists.txt` falha no configure se
  o prefixo do `/showIncludes` não for detectado. Um diretório configurado fora
  do Developer Command Prompt gravava o prefixo errado e o ninja parava de
  rebuildar em mudança de header — falha que só aparecia depois, como objeto
  obsoleto linkado contra uma ABI alterada. O servidor passa a ser publicado em
  `install/bin` (`-Install`), para que um servidor MCP em execução não bloqueie
  mais o link com `LNK1104`. A leitura de `rules.ninja` força UTF-8 no
  Windows PowerShell 5.1, preservando prefixos localizados;
- `memory_debug.inspect_address` ([Spec 0011](docs/specs/0011-inspect-address.md)):
  correlaciona um endereço com região, proteções, módulo/RVA e candidatos
  rankeados de objeto/vtable numa resposta pequena e somente-leitura. Toda
  classificação é `probable`, com confiança, evidências (`observed`/`sampled`) e
  proveniência auditáveis; ausência vira `null`/vazio/limitação tipada, nunca
  sentinela. `pointer_size` é obrigatório e nunca herdado do host. Referências
  são opt-in: `live_scan` com orçamento explícito, cobertura e `resume_token`
  assinado e vinculado à consulta — uma lista vazia só é conclusiva com
  cobertura completa. `mode: "index"` é recusado com `unsupported` até a
  Spec 0010 existir, em vez de virar um `live_scan` silencioso;
- reflexão Unreal em runtime sem PDB
  ([Spec 0012](docs/specs/0012-unreal-runtime-reflection.md)):
  `memory_debug.unreal_runtime_discover`/`classes`/`type`/`objects`/`release`,
  com perfis versionados `ue5-fproperty-x64` e `ue4-uproperty-x64` selecionados
  explicitamente e sem fallback entre si. Enumera `GUObjectArray`, resolve
  `FNamePool`, classes, herança e `FProperty`/`UProperty` com offsets. Cada
  página é relida e comparada por digest de tuples `(slot, object, serial)` —
  contagens sozinhas não detectam um slot reciclado — e um alvo instável
  termina em `unstable_snapshot` sem publicar catálogo parcial. Nasce desligada
  atrás de `ARGOS_MCP_ENABLE_UNREAL_RUNTIME` mais allowlist de perfil, com um
  segundo gate para descoberta automática; as tools nem aparecem em `tools/list`
  enquanto isso. Valores de instância ficam fora da resposta. PDB permanece uma
  fonte separada e preferida para layout nativo. Nesta entrega, `discover` e
  `objects` são síncronos e limitados; `mode: "explicit"` é o caminho funcional,
  enquanto `mode: "profile"` não possui fingerprints registrados e
  `mode: "auto"` permanece indisponível até a composição multipadrão;
- higiene de distribuição: relatórios de sessão e configurações locais antigas
  foram removidos da raiz; configuração, contratos e estado da implementação
  ficam concentrados em `README.md`, `docs/`, `.mcp.json` e neste changelog;

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

# Argos Runtime Memory Debug MCP

Servidor MCP local em C++23 para depuração autorizada de memória em runtime. O transporte padrão é `stdio`; todas as mensagens de protocolo usam `stdout` e logs estruturados são enviados exclusivamente para `stderr`.

## Escopo de segurança

Use somente em processos próprios ou em sistemas para os quais exista autorização explícita de depuração. Por padrão, o servidor não implementa injeção. No Windows, a bridge de depuração Argos é uma exceção opt-in e limitada a DLLs explicitamente aprovadas pelo operador; ela não aceita código, exports ou argumentos arbitrários. O servidor não oferece alteração de proteção de páginas, bypass de anticheat/EDR, ocultação, captura de credenciais ou elevação de privilégio.

Por padrão:

- somente processos do mesmo usuário podem ser anexados;
- sessões são somente leitura;
- escrita de memória exige sessão read-write explícita e a frase de confirmação por chamada;
- leituras e scans possuem limites rígidos;
- cada `attach` exige `authorized: true`;
- cada escrita exige a frase `AUTHORIZED_DEBUG_WRITE`.

## Tools MCP

Tipos e layouts vêm sempre com origem e nível de confiança explícitos; scans e
assinaturas permanecem candidatos e não são promovidos a layout confirmado.

| Tool | Função |
|---|---|
| `memory_debug_process_list` | Lista processos locais e informa correspondência de usuário. |
| `memory_debug_attach` | Abre uma sessão explícita para um PID autorizado. |
| `memory_debug_detach` | Fecha a sessão e libera handles; `terminate: true` encerra sessões criadas por `launch`. |
| `memory_debug_sessions` | Lista sessões ativas. |
| `memory_debug_regions` | Lista regiões de memória e permissões, com filtro por atributo/tamanho/nome e paginação aplicados no servidor. |
| `memory_debug_address_space_summary` | Agrega tamanho e contagem do espaço de endereçamento por classe; dimensiona o alvo antes de varrer. |
| `memory_debug_modules` | Lista módulos carregados/mapeamentos de arquivo. |
| `memory_debug_pdb_list_types` | Enumera tipos disponíveis no PDB de um módulo carregado. |
| `memory_debug_pdb_type` | Consulta o layout de um tipo no PDB correspondente ao módulo carregado. |
| `memory_debug_unity_type` | Extrai tipos de `global-metadata.dat` IL2CPP e usa PDB para completar offsets. |
| `memory_debug_unreal_type` | Extrai tipos UHT do PDB nativo. |
| `memory_debug_unreal_reflection` | Extrai símbolos de reflexão UHT do PDB nativo. |
| `memory_debug_read` | Lê bytes limitados e retorna hexadecimal. |
| `memory_debug_read_batch` | Executa múltiplas leituras limitadas, coalescendo intervalos adjacentes/sobrepostos em uma única leitura nativa. |
| `memory_debug_read_typed` | Decodifica inteiros, floats e UTF-8 little-endian. |
| `memory_debug_strings` | Extrai strings ASCII/UTF-16LE legíveis da memória do processo. |
| `memory_debug_scan_exact` | Busca um padrão exato de bytes com orçamento explícito. |
| `memory_debug_scan_pointers_to` | Busca ponteiros que referenciam um endereço conhecido. |
| `memory_debug_scan_pointer_chains` | Descobre cadeias reversas estáveis com uma única passagem multi-alvo por profundidade. |
| `memory_debug_scan_first` / `scan_next` / `scan_results` / `scan_reset` | Scan incremental (first scan/next scan) para localizar offsets de campos dinâmicos sem PDB/RTTI. `scan_first` e `scan_next` aceitam decimal; cobertura e páginas trazem metadados completos. |
| `memory_debug_inspect_address` | Correlaciona um endereço com região, proteções, módulo/RVA e candidatos **prováveis** de objeto/vtable, com referências opcionais dentro de orçamento explícito. |
| `memory_debug_disassemble` | Desmonta x86/x64 somente leitura a partir de um endereço, resolvendo branches relativos e operandos RIP-relativos para alvos absolutos (ADR-0029). |
| `memory_debug_find_code_references` | Varre memória executável e devolve as instruções que referenciam um endereço-alvo (quem lê/escreve um slot, quem chama uma função). Evidência de referência, não limite de função. |
| `memory_debug_resolve_pointer_chain` | Resolve pointer chains de 32 ou 64 bits. |
| `memory_debug_write` | Escreve bytes somente quando habilitado e confirmado. |
| `memory_debug_launch` / `read_output` | Inicia um executável escolhido pelo operador e captura `stdout`/`stderr`. Desligado por padrão (`ARGOS_MCP_ALLOW_LAUNCH`). |
| `memory_debug_debug_bridge_inject` | Carrega uma DLL bridge do próprio Argos, explicitamente aprovada, em uma sessão autorizada do Windows. Desligada por padrão (`ARGOS_MCP_ALLOW_DEBUG_BRIDGE_INJECTION`). Não aceita código, exports ou argumentos arbitrários. |
| `memory_debug_scan_start` | Inicia `scan_exact`/`strings`/`scan_pointers_to`/`scan_pointer_chains`/`scan_first`/`scan_next` como job em background que sobrevive à chamada MCP ([Spec 0008](docs/specs/0008-async-scan-operations.md)). |
| `memory_debug_job_status` | Consulta estado, progresso monotônico e motivo de término de um job em background. |
| `memory_debug_job_results` | Pagina o resultado imutável de um job terminal. |
| `memory_debug_job_cancel` | Pede cancelamento cooperativo de um job em fila ou em execução; idempotente após terminal. |
| `memory_debug_job_release` | Libera resultados e estado retido de um job terminal. |

Atrás de gate, desligadas por padrão (`ARGOS_MCP_ENABLE_UNREAL_RUNTIME` mais
uma allowlist de perfis) e ausentes de `tools/list` enquanto isso:

| Tool | Função |
|---|---|
| `memory_debug_unreal_runtime_discover` | Valida as raízes `GUObjectArray`/`FNamePool` contra um perfil de layout habilitado e publica um contexto somente-leitura com o catálogo de classes. |
| `memory_debug_unreal_runtime_classes` | Pagina o catálogo de classes validado, com filtro por nome. |
| `memory_debug_unreal_runtime_type` | Lê `FProperty`/`UProperty` declaradas e herdadas de uma classe do catálogo: offsets e tamanhos, nunca valores de instância. |
| `memory_debug_unreal_runtime_objects` | Enumera summaries de `UObject` vivos filtrados por classe, página a página. |
| `memory_debug_unreal_runtime_release` | Libera o contexto e os catálogos derivados. |

Atrás de gate próprio (`ARGOS_MCP_ENABLE_SANTAMONICA_RUNTIME` **mais** um perfil
de build ou o peer controlado) e ausentes de `tools/list` enquanto isso. Elas
leem, com perfil de build, a tabela de tipos da build real pela sessão
autorizada, somente leitura; sem perfil, falam com o peer sintético da
[ADR-0025](docs/adr/0025-santa-monica-local-channel.md). Em nenhum caso
escrevem, injetam ou iniciam processo. Esta build não expõe campos, enums nem
SLI, e as páginas correspondentes vêm vazias em vez de inventadas.

| Tool | Função |
|---|---|
| `memory_debug_santamonica_runtime_discover` | Publica um snapshot somente leitura: da build real quando há perfil casando ([ADR-0026](docs/adr/0026-santa-monica-native-type-reader.md)), do peer controlado caso contrário. |
| `memory_debug_santamonica_runtime_types` | Pagina os tipos do snapshot, com filtro por nome. |
| `memory_debug_santamonica_runtime_type` | Lê um tipo com campos declarados e, opcionalmente, herdados. |
| `memory_debug_santamonica_runtime_enums` | Pagina enums e valores, preservando a grafia decimal exata de 64 bits. |
| `memory_debug_santamonica_runtime_sli_functions` | Pagina entradas SLI descritivas, sempre com `invocable: false`. |
| `memory_debug_santamonica_runtime_release` | Libera o snapshot e as páginas derivadas. |

## Roadmap

`inspect_address`, a reflexão Unreal em runtime e o scan assíncrono estão
implementados ([Spec 0011](docs/specs/0011-inspect-address.md),
[Spec 0012](docs/specs/0012-unreal-runtime-reflection.md),
[Spec 0008](docs/specs/0008-async-scan-operations.md)), com os limites de
escopo descritos em cada spec — em particular, retomada por `resume_token`
na Spec 0008 é um ponto de extensão ainda não implementado. Continuam
**propostas e fora das tools acima**: importação/multipadrão ([Spec
0009](docs/specs/0009-scan-composition-and-multi-pattern.md)) e índice
persistente de pointer chains ([Spec
0010](docs/specs/0010-persistent-pointer-index.md)). Contratos, decisões,
riscos e ordem de implementação estão no [roadmap de eficiência do
agente](docs/specs/0007-roadmap-eficiencia-agente.md).

## Plataformas

- Windows: `Toolhelp32Snapshot`, `OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory` e `WriteProcessMemory`.
- Linux: `/proc`, `process_vm_readv` e `process_vm_writev`.
- macOS: retorna `unsupported` nesta versão.

As permissões do sistema operacional continuam sendo aplicadas. No Linux, políticas de `ptrace_scope`, namespaces e sandbox podem bloquear acesso mesmo para processos do mesmo usuário. No Windows, integridade, elevação e processos protegidos podem impedir `OpenProcess`.

## Compilar

Requisitos:

- CMake 3.25 ou superior;
- compilador com C++23: MSVC, Clang ou GCC;
- Ninja para os presets fornecidos.

O desmontador (ADR-0029) usa [Zydis](https://github.com/zyantific/zydis) v4.1.1
(Zycore `0b2432c`), licença MIT, vendorizado em `third_party/zydis` e compilado
como biblioteca estática pelo próprio build — sem dependência de rede, pacote de
sistema ou submódulo a inicializar.

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

### Windows (MSVC + Ninja)

Use o script, que prepara o ambiente antes de tocar no CMake:

```powershell
.\tools\build.ps1 -Preset dev
```

O diretório de build **precisa ser configurado** com `cl.exe` no `PATH`. O Ninja
rastreia dependências de header lendo o `/showIncludes` do MSVC, cujo prefixo é
localizado; o CMake descobre esse prefixo perguntando ao compilador durante o
configure. Configurar fora de um Developer Command Prompt grava o prefixo errado
e **mudanças em header deixam de disparar rebuild** — o sintoma aparece bem
depois, como um objeto obsoleto linkado contra uma ABI que mudou, e não como
erro de build. O `CMakeLists.txt` falha no configure se o prefixo não for
detectado, e `tools/build.ps1` compara o prefixo gravado com o que o compilador
realmente imprime, reconfigurando do zero quando divergem.

Release:

IPO/LTO pode ser testado com `-DARGOS_ENABLE_IPO=ON`, mas permanece desligado
no preset Release: o benchmark de protocolo em MSVC reduziu o binário em 3,1%,
porém perdeu 6,4% de throughput em `tools/list`.

```bash
cmake --preset release
cmake --build --preset release
ctest --test-dir build/release --output-on-failure
```

Sanitizers:

```bash
cmake --preset asan
cmake --build --preset asan
ctest --preset asan
```

TSan deve ser executado em build separada:

```bash
cmake --preset tsan
cmake --build --preset tsan
ctest --test-dir build/tsan --output-on-failure
```

## Executável de teste

`argos_memory_target` mantém um padrão conhecido na memória e imprime PID, endereço e bytes esperados:

```bash
./build/dev/argos_memory_target
```

Exemplo de saída:

```text
pid=12345 address=0x7FFD12340000 pattern=4152474f532d4d43502d544553542100
```

## Configuração do cliente MCP

Aponte o cliente para uma cópia **instalada**, não para a árvore de build. O
servidor mantém o executável aberto enquanto roda, então um cliente apontado
para `build/release` faz o próximo link falhar com `LNK1104`:

```powershell
.\tools\build.ps1 -Preset release -Install
```

Isso publica em `install\bin\argos_runtime_memory_mcp.exe` — o caminho usado por
`.mcp.json`. Rebuilds deixam de disputar o arquivo com o servidor; reinstale e
reinicie o cliente quando quiser que ele passe a usar o código novo.

Exemplo genérico:

```json
{
  "mcpServers": {
    "argos-memory": {
      "command": "C:/caminho/argos_runtime_memory_mcp.exe",
      "args": [],
      "env": {
        "ARGOS_MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Arquivos de exemplo estão em `examples/`.

## Habilitar escrita

A escrita permanece desabilitada até o processo do servidor ser iniciado com:

Windows PowerShell:

```powershell
$env:ARGOS_MCP_ALLOW_WRITE = "1"
.\build\dev\argos_runtime_memory_mcp.exe
```

Linux:

```bash
ARGOS_MCP_ALLOW_WRITE=1 ./build/dev/argos_runtime_memory_mcp
```

Depois disso, o `attach` deve solicitar `access: "read_write"`, e cada chamada de `memory_debug_write` deve enviar `confirmation: "AUTHORIZED_DEBUG_WRITE"`.

## Variáveis de ambiente

| Variável | Padrão | Limite rígido |
|---|---:|---:|
| `ARGOS_MCP_ALLOW_WRITE` | `1` | booleano (`0` restaura o modo somente leitura) |
| `ARGOS_MCP_ALLOW_FOREIGN_USER` | `0` | booleano |
| `ARGOS_MCP_MAX_READ_BYTES` | 65.536 | 1 MiB |
| `ARGOS_MCP_MAX_WRITE_BYTES` | 4.096 | 64 KiB |
| `ARGOS_MCP_MAX_SCAN_BYTES` | 32 MiB | 256 MiB |
| `ARGOS_MCP_MAX_SCAN_RESULTS` | 256 | 4.096 |
| `ARGOS_MCP_MAX_STRING_RESULT_LENGTH` | 256 | 4.096 |
| `ARGOS_MCP_MAX_SCAN_SESSION_CANDIDATES` | 262.144 | 4.194.304 |
| `ARGOS_MCP_MAX_SCAN_SESSIONS_PER_SESSION` | 4 | 64 |
| `ARGOS_MCP_ALLOW_LAUNCH` | `0` | booleano |
| `ARGOS_MCP_ALLOW_DEBUG_BRIDGE_INJECTION` | `0` | booleano |
| `ARGOS_MCP_DEBUG_BRIDGE_ALLOWED_PATHS` | (vazio = nenhuma) | lista de caminhos absolutos de DLL separados por `;` |
| `ARGOS_MCP_LAUNCH_ALLOWED_DIRS` | (vazio = sem allowlist) | lista separada por `;` |
| `ARGOS_MCP_MAX_LAUNCHED_PROCESSES` | 4 | 64 |
| `ARGOS_MCP_MAX_CAPTURED_OUTPUT_BYTES` | 1 MiB | 64 MiB |
| `ARGOS_MCP_MAX_ASYNC_JOBS_TOTAL` | 64 | 1.024 |
| `ARGOS_MCP_MAX_ASYNC_JOBS_PER_SESSION` | 8 | 128 |
| `ARGOS_MCP_MAX_ASYNC_QUEUE_DEPTH` | 32 | 512 |
| `ARGOS_MCP_MAX_ASYNC_WORKERS` | 2 | 16 |
| `ARGOS_MCP_MAX_ASYNC_JOB_BYTE_BUDGET` | 256 MiB | 4 GiB |
| `ARGOS_MCP_MAX_ASYNC_JOB_DEADLINE_MS` | 600.000 (10 min) | 3.600.000 (1 h) |
| `ARGOS_MCP_MAX_ASYNC_JOB_RESULT_ITEMS` | 4.096 | 65.536 |
| `ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES` | 64 MiB | 1 GiB |
| `ARGOS_MCP_ASYNC_RESULTS_TTL_MS` | 300.000 (5 min) | 3.600.000 (1 h) |
| `ARGOS_MCP_ASYNC_TOMBSTONE_TTL_MS` | 60.000 (1 min) | 600.000 (10 min) |
| `ARGOS_MCP_MAX_INSPECT_LOOKBEHIND_BYTES` | 16 KiB | 16 KiB |
| `ARGOS_MCP_MAX_INSPECT_VTABLE_PROBES` | 128 | 128 |
| `ARGOS_MCP_MAX_INSPECT_VTABLE_ENTRIES` | 64 | 64 |
| `ARGOS_MCP_MAX_INSPECT_OBJECT_CANDIDATES` | 64 | 64 |
| `ARGOS_MCP_ENABLE_UNREAL_RUNTIME` | `0` | booleano |
| `ARGOS_MCP_ENABLE_UNREAL_AUTO_DISCOVERY` | `0` | booleano |
| `ARGOS_MCP_UNREAL_PROFILES` | (vazio = nenhum perfil habilitado) | lista separada por `;` |
| `ARGOS_MCP_UNREAL_BUILD_PROFILES` | (vazio) | até 64 registros / 32 KiB |
| `ARGOS_MCP_MAX_UNREAL_CONTEXTS_PER_SESSION` | 2 | 16 |
| `ARGOS_MCP_MAX_UNREAL_CONTEXTS` | 8 | 64 |
| `ARGOS_MCP_MAX_UNREAL_SLOTS` | 1.000.000 | 8.000.000 |
| `ARGOS_MCP_MAX_UNREAL_OBJECTS` | 10.000 | 100.000 |
| `ARGOS_MCP_MAX_UNREAL_CLASSES` | 20.000 | 200.000 |
| `ARGOS_MCP_MAX_UNREAL_PROPERTIES` | 1.024 | 8.192 |
| `ARGOS_MCP_MAX_UNREAL_SUPER_DEPTH` | 64 | 256 |
| `ARGOS_MCP_MAX_UNREAL_PROPERTY_NODES` | 4.096 | 32.768 |
| `ARGOS_MCP_MAX_UNREAL_NAME_BYTES` | 1.024 | 4.096 |
| `ARGOS_MCP_MAX_UNREAL_PAGE_RETRIES` | 2 | 8 |
| `ARGOS_MCP_MAX_UNREAL_CONTEXT_BYTES` | 64 MiB | 256 MiB |
| `ARGOS_MCP_UNREAL_CONTEXT_TTL_SECONDS` | 900 | 3.600 |
| `ARGOS_MCP_ENABLE_SANTAMONICA_RUNTIME` | `0` | booleano |
| `ARGOS_MCP_SANTAMONICA_PEER` | (vazio) | caminho absoluto do peer controlado |
| `ARGOS_MCP_SANTAMONICA_BUILD_PROFILES` | (vazio) | até 16 registros / 8 KiB |
| `ARGOS_MCP_MAX_SANTAMONICA_CONTEXTS_PER_SESSION` | 1 | 8 |
| `ARGOS_MCP_MAX_SANTAMONICA_CONTEXTS` | 2 | 16 |
| `ARGOS_MCP_MAX_SANTAMONICA_RECORDS` | 100.000 | 100.000 |
| `ARGOS_MCP_MAX_SANTAMONICA_STRING_BYTES` | 4.096 | 4.096 |
| `ARGOS_MCP_MAX_SANTAMONICA_RETAINED_BYTES` | 32 MiB | 32 MiB |
| `ARGOS_MCP_MAX_SANTAMONICA_FIELDS` | 1.024 | 4.096 |
| `ARGOS_MCP_MAX_SANTAMONICA_ENUM_VALUES` | 1.024 | 4.096 |
| `ARGOS_MCP_MAX_SANTAMONICA_SESSION_MS` | 10.000 | 60.000 |
| `ARGOS_MCP_SANTAMONICA_CONTEXT_TTL_SECONDS` | 900 | 3.600 |
| `ARGOS_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` |

Os limites de `inspect_address` só podem ser **reduzidos** pelo operador: o teto
rígido do domínio continua sendo o limite superior.

`ARGOS_MCP_ENABLE_SANTAMONICA_RUNTIME=1` sozinho também não habilita nada: é
preciso uma das duas origens, `ARGOS_MCP_SANTAMONICA_PEER` (peer controlado) ou
`ARGOS_MCP_SANTAMONICA_BUILD_PROFILES` (perfil de build lido nativamente).
Com um perfil casando o módulo carregado da sessão, `discover` lê a build real;
sem perfil, usa o peer. A resposta sempre declara a origem em `source`. O peer é o alvo sintético controlado descrito na
[ADR-0025](docs/adr/0025-santa-monica-local-channel.md), publicado em
`install\bin\argos_santa_monica_peer.exe`; ele prova o protocolo, não a
compatibilidade com uma build do jogo.

A reflexão nativa usa `gow2018-reflection-x64-v2` e o formato de perfil da
[ADR-0027](docs/adr/0027-santa-monica-native-reflection.md): nove campos para
tipos, quinze para acrescentar atributos, enums e SLI, ou dezesseis para
publicar também o inventário de recursos
([ADR-0028](docs/adr/0028-santa-monica-resources-and-execution.md)) com
`santamonica_runtime_resources` e `santamonica_runtime_set_resource` — esta é
escrita direta de saldo, não concessão da engine. A família antiga
`gow2018-typetable-x64` é recusada; a migração exige corrigir também os RVAs.
Na instalação validada, o MCP publica 1.192 tipos, 7.041 campos, 482 enums,
3.791 valores e 309 funções SLI. A cobertura é parcial e SLI é descritivo;
invocação, inventário e Lua permanecem pendentes.

`ARGOS_MCP_ENABLE_UNREAL_RUNTIME=1` sozinho não habilita nada. Um perfil precisa
ser nomeado em `ARGOS_MCP_UNREAL_PROFILES` (allowlist vazia = nenhum perfil), e
`mode: "auto"` exige o segundo gate. Uma requisição nunca liga um gate.

Builds conhecidas podem ser registradas sem expor roots ao cliente:

```text
build_id|profile_id|module_name|module_size_decimal|signature_rva_hex|signature_hex|gu_object_array_rva_hex|fname_pool_rva_hex
```

Registros são separados por `;`. A assinatura deve conter 8–64 bytes e todos
os RVAs precisam estar dentro de `module_size`. `mode: "profile"` usa esse
registro diretamente; `mode: "auto"` tenta registros exatos antes do fallback
multipadrão ainda não implementado. Nome, tamanho e assinatura precisam
corresponder, e as invariantes completas do runtime ainda são validadas.

`ARGOS_MCP_ALLOW_FOREIGN_USER=1` remove somente a validação interna de proprietário. Ele não contorna permissões do sistema operacional e deve ser usado apenas em ambientes de laboratório controlados.

`ARGOS_MCP_ALLOW_LAUNCH=1` habilita `memory_debug_launch` (o servidor cria um processo em vez de apenas ler um já existente). Desligado por padrão; útil apenas para alvos de teste/desenvolvimento controlados pelo próprio operador, não para anexar a processos de terceiros já em execução. Ver o threat model para os controles completos.

## Habilitar bridge de depuração no Windows

`memory_debug_debug_bridge_inject` é uma capacidade separada de escrita de
memória. Ela só aparece quando o servidor inicia com os dois controles abaixo:

```powershell
$env:ARGOS_MCP_ALLOW_DEBUG_BRIDGE_INJECTION = "1"
$env:ARGOS_MCP_DEBUG_BRIDGE_ALLOWED_PATHS = "C:\\caminho\\argos_debug_bridge.dll"
```

A tool exige `authorized: true` em cada chamada, e o caminho deve ser
exatamente um arquivo regular listado na allowlist após canonicalização. A
bridge inicial distribuída pelo projeto apenas comprova carregamento; ela não
instala hooks nem recebe comandos. Consulte [ADR-0021](docs/adr/0021-opt-in-debug-bridge-injection.md) antes de habilitar a capacidade.

As variáveis `ARGOS_MCP_MAX_ASYNC_*` e `ARGOS_MCP_ASYNC_*` limitam `AnalysisJobManager` (jobs em background da Spec 0008): fila global/por sessão, pool de workers, orçamento de bytes e deadline por job, itens de resultado por página e TTL de resultado/tombstone. Nenhum valor pedido pelo cliente em `execution` ultrapassa esses limites — apenas reduz. `ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES` é um limite **agregado**, somado sobre os resultados retidos de todos os jobs simultaneamente (não por job): a contabilidade inclui o conteúdo alocado no heap de cada match (texto de `strings`, offsets de `scan_pointer_chains`), não só `size() * sizeof(T)`. Quando um job termina e a retenção de seus resultados estouraria o agregado, o job mantém o quanto couber (a cobertura do scan pode continuar `coverage_complete: true`) e o excedente é descartado com `termination.truncated: true`, `results_complete: false` e `truncation_reasons` incluindo `"retained_bytes_budget"` — nunca um descarte silencioso. `job_release`, a expiração do TTL de resultados e `detach_session` devolvem os bytes ao orçamento agregado.

## Skills instaladas

As skills C++ estão instaladas no projeto em `.skills/`. O arquivo `AGENTS.md` define quando cada uma é obrigatória. Para copiar o pacote para o diretório global do Codex:

```powershell
.\tools\install-skills.ps1
```

ou:

```bash
./tools/install-skills.sh
```

## Arquitetura

```text
MCP stdio transport
        ↓
JSON-RPC dispatcher
        ↓
Tool catalog / validation / presentation
        ↓
MemoryDebugService / SessionManager / SecurityPolicy
        ↓
ProcessMemoryProvider interface
        ↓
Windows or Linux native implementation
```

O domínio não depende de JSON, MCP, `stdin`, `stdout` ou APIs específicas do sistema operacional.

## Unity, Unreal e PDB

O caminho de maior confianca implementado e `memory_debug_pdb_type`, usando
DbgHelp no Windows para consultar o PDB correspondente ao modulo carregado.
Unity e Unreal possuem metadados dependentes do backend/versao; o metodo
recomendado e os limites oficiais estao em
[`docs/engines/unity-unreal-pdb.md`](docs/engines/unity-unreal-pdb.md).
Scans e assinaturas continuam sendo candidatos e nao sao promovidos a layout
confirmado.

Uma extensão somente-leitura por perfis de runtime (`GUObjectArray`,
`FNamePool`, classes e `FProperty`) está implementada conforme a
[Spec 0012](docs/specs/0012-unreal-runtime-reflection.md) e nasce desligada.
Ela **não** altera a proveniência das tools PDB atuais: `unreal:runtime-reflection`
é uma fonte separada, com confiança e evidências próprias, e o PDB continua
sendo o caminho preferido para layout nativo completo. Perfis embutidos:
`ue5-fproperty-x64` (`FField`/`FProperty`) e `ue4-uproperty-x64`
(`UField`/`UProperty`), selecionados explicitamente e sem fallback entre si.

## Santa Monica/Kinetica (em desenvolvimento)

O suporte por build para a engine proprietária de *God of War* (2018) está
em implementação incremental. A etapa 1 está fechada e o servidor já lê tipos
reais da build Steam 11168363: catálogo validado no domínio, codec de snapshot
([ADR-0023](docs/adr/0023-santa-monica-reflection-stream.md)), handshake
autenticado ([ADR-0024](docs/adr/0024-santa-monica-bridge-handshake.md)),
canal local com ACL e bootstrap
([ADR-0025](docs/adr/0025-santa-monica-local-channel.md)), manager com quotas e
TTL, e seis tools MCP somente leitura atrás de gate. Elas funcionam ponta a
ponta contra um **peer sintético controlado** e, com perfil de build
([ADR-0027](docs/adr/0027-santa-monica-native-reflection.md)), contra o jogo
real, publicando tipos, herança, campos próprios, enums/valores e funções SLI
descritivas. A cobertura é parcial: coleções auxiliares, mapas sem tamanho
comprovado e propriedades SLI ficam de fora. Inventário, gameplay e Lua
continuam pendentes. O plano aprovado inclui RTTI, SLI, Lua,
inventário e operações de gameplay por bridge, sempre vinculadas a um perfil
exato e a gates opt-in. O plano começa por reflexão somente leitura; bridge
com canal autenticado, gameplay com deduplicação e Lua com isolamento são
etapas posteriores, condicionadas à validação da build. Consulte
[`docs/engines/santa-monica-kinetica.md`](docs/engines/santa-monica-kinetica.md),
[Spec 0014](docs/specs/0014-santa-monica-kinetica-runtime-instrumentation.md)
e [ADR-0022](docs/adr/0022-santa-monica-kinetica-runtime-instrumentation.md).

## Licença

MIT. Consulte `LICENSE`.

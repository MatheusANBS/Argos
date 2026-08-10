# Argos Runtime Memory Debug MCP

Servidor MCP local em C++23 para depuração autorizada de memória em runtime. O transporte padrão é `stdio`; todas as mensagens de protocolo usam `stdout` e logs estruturados são enviados exclusivamente para `stderr`.

## Escopo de segurança

Use somente em processos próprios ou em sistemas para os quais exista autorização explícita de depuração. O servidor não implementa injeção de código, DLL injection, criação de threads remotas, alteração de proteção de páginas, bypass de anticheat/EDR, ocultação, captura de credenciais ou elevação de privilégio.

Por padrão:

- somente processos do mesmo usuário podem ser anexados;
- sessões são somente leitura;
- escrita de memória fica desabilitada;
- leituras e scans possuem limites rígidos;
- cada `attach` exige `authorized: true`;
- cada escrita exige a frase `AUTHORIZED_DEBUG_WRITE`.

## Tools MCP

Tipos e layouts vêm sempre com origem e nível de confiança explícitos; scans e
assinaturas permanecem candidatos e não são promovidos a layout confirmado.

| Tool | Função |
|---|---|
| `memory_debug.process_list` | Lista processos locais e informa correspondência de usuário. |
| `memory_debug.attach` | Abre uma sessão explícita para um PID autorizado. |
| `memory_debug.detach` | Fecha a sessão e libera handles; `terminate: true` encerra sessões criadas por `launch`. |
| `memory_debug.sessions` | Lista sessões ativas. |
| `memory_debug.regions` | Lista regiões de memória e permissões, com filtro por atributo/tamanho/nome e paginação aplicados no servidor. |
| `memory_debug.address_space_summary` | Agrega tamanho e contagem do espaço de endereçamento por classe; dimensiona o alvo antes de varrer. |
| `memory_debug.modules` | Lista módulos carregados/mapeamentos de arquivo. |
| `memory_debug.pdb_list_types` | Enumera tipos disponíveis no PDB de um módulo carregado. |
| `memory_debug.pdb_type` | Consulta o layout de um tipo no PDB correspondente ao módulo carregado. |
| `memory_debug.unity_type` | Extrai tipos de `global-metadata.dat` IL2CPP e usa PDB para completar offsets. |
| `memory_debug.unreal_type` | Extrai tipos UHT do PDB nativo. |
| `memory_debug.unreal_reflection` | Extrai símbolos de reflexão UHT do PDB nativo. |
| `memory_debug.read` | Lê bytes limitados e retorna hexadecimal. |
| `memory_debug.read_batch` | Executa múltiplas leituras limitadas, coalescendo intervalos adjacentes/sobrepostos em uma única leitura nativa. |
| `memory_debug.read_typed` | Decodifica inteiros, floats e UTF-8 little-endian. |
| `memory_debug.strings` | Extrai strings ASCII/UTF-16LE legíveis da memória do processo. |
| `memory_debug.scan_exact` | Busca um padrão exato de bytes com orçamento explícito. |
| `memory_debug.scan_pointers_to` | Busca ponteiros que referenciam um endereço conhecido. |
| `memory_debug.scan_pointer_chains` | Descobre cadeias reversas estáveis com uma única passagem multi-alvo por profundidade. |
| `memory_debug.scan_first` / `scan_next` / `scan_results` / `scan_reset` | Scan incremental (first scan/next scan) para localizar offsets de campos dinâmicos sem PDB/RTTI. `scan_first` e `scan_next` aceitam decimal; cobertura e páginas trazem metadados completos. |
| `memory_debug.resolve_pointer_chain` | Resolve pointer chains de 32 ou 64 bits. |
| `memory_debug.write` | Escreve bytes somente quando habilitado e confirmado. |
| `memory_debug.launch` / `read_output` | Inicia um executável escolhido pelo operador e captura `stdout`/`stderr`. Desligado por padrão (`ARGOS_MCP_ALLOW_LAUNCH`). |
| `memory_debug.scan_start` | Inicia `scan_exact`/`strings`/`scan_pointers_to`/`scan_pointer_chains`/`scan_first`/`scan_next` como job em background que sobrevive à chamada MCP ([Spec 0008](docs/specs/0008-async-scan-operations.md)). |
| `memory_debug.job_status` | Consulta estado, progresso monotônico e motivo de término de um job em background. |
| `memory_debug.job_results` | Pagina o resultado imutável de um job terminal. |
| `memory_debug.job_cancel` | Pede cancelamento cooperativo de um job em fila ou em execução; idempotente após terminal. |
| `memory_debug.job_release` | Libera resultados e estado retido de um job terminal. |

## Roadmap proposto

`docs/specs/` contém tanto specs já implementadas quanto propostas. As
seguintes estão **especificadas mas não implementadas** — nenhuma tool acima as
expõe:

| Proposta | Spec | ADR |
|---|---|---|
| Composição de scan e multipadrão | [0009](docs/specs/0009-scan-composition-and-multi-pattern.md) | [0017](docs/adr/0017-scan-composition-and-multi-pattern.md) |
| Índice persistente de ponteiros | [0010](docs/specs/0010-persistent-pointer-index.md) | [0018](docs/adr/0018-persistent-pointer-index.md) |
| `inspect_address` e evidência derivada | [0011](docs/specs/0011-inspect-address.md) | [0013](docs/adr/0013-address-inspection-derived-evidence.md) |
| Reflexão Unreal em runtime sem PDB | [0012](docs/specs/0012-unreal-runtime-reflection.md) | [0019](docs/adr/0019-unreal-runtime-reflection.md) |

Riscos, ordem de implementação e o protocolo de teste com valor mutável estão
no [roadmap de eficiência do agente](docs/specs/0007-roadmap-eficiencia-agente.md).

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

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

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

Depois disso, o `attach` deve solicitar `access: "read_write"`, e cada chamada de `memory_debug.write` deve enviar `confirmation: "AUTHORIZED_DEBUG_WRITE"`.

## Variáveis de ambiente

| Variável | Padrão | Limite rígido |
|---|---:|---:|
| `ARGOS_MCP_ALLOW_WRITE` | `0` | booleano |
| `ARGOS_MCP_ALLOW_FOREIGN_USER` | `0` | booleano |
| `ARGOS_MCP_MAX_READ_BYTES` | 65.536 | 1 MiB |
| `ARGOS_MCP_MAX_WRITE_BYTES` | 4.096 | 64 KiB |
| `ARGOS_MCP_MAX_SCAN_BYTES` | 32 MiB | 256 MiB |
| `ARGOS_MCP_MAX_SCAN_RESULTS` | 256 | 4.096 |
| `ARGOS_MCP_MAX_STRING_RESULT_LENGTH` | 256 | 4.096 |
| `ARGOS_MCP_MAX_SCAN_SESSION_CANDIDATES` | 262.144 | 4.194.304 |
| `ARGOS_MCP_MAX_SCAN_SESSIONS_PER_SESSION` | 4 | 64 |
| `ARGOS_MCP_ALLOW_LAUNCH` | `0` | booleano |
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
| `ARGOS_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` |

`ARGOS_MCP_ALLOW_FOREIGN_USER=1` remove somente a validação interna de proprietário. Ele não contorna permissões do sistema operacional e deve ser usado apenas em ambientes de laboratório controlados.

`ARGOS_MCP_ALLOW_LAUNCH=1` habilita `memory_debug.launch` (o servidor cria um processo em vez de apenas ler um já existente). Desligado por padrão; útil apenas para alvos de teste/desenvolvimento controlados pelo próprio operador, não para anexar a processos de terceiros já em execução. Ver o threat model para os controles completos.

As variáveis `ARGOS_MCP_MAX_ASYNC_*` e `ARGOS_MCP_ASYNC_*` limitam `AnalysisJobManager` (jobs em background da Spec 0008): fila global/por sessão, pool de workers, orçamento de bytes e deadline por job, itens de resultado por página e TTL de resultado/tombstone. Nenhum valor pedido pelo cliente em `execution` ultrapassa esses limites — apenas reduz. `ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES` está reservado para um limite agregado explícito de bytes retidos entre todos os jobs; nesta versão a memória retida já é indiretamente limitada por `ARGOS_MCP_MAX_ASYNC_JOBS_TOTAL`/`_PER_SESSION` combinados com os limites de itens por operação (`ARGOS_MCP_MAX_SCAN_RESULTS`, `ARGOS_MCP_MAX_SCAN_SESSION_CANDIDATES`), mas a variável ainda não é somada e comparada ativamente — ver o relatório de implementação.

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

O caminho de maior confianca implementado e `memory_debug.pdb_type`, usando
DbgHelp no Windows para consultar o PDB correspondente ao modulo carregado.
Unity e Unreal possuem metadados dependentes do backend/versao; o metodo
recomendado e os limites oficiais estao em
[`docs/engines/unity-unreal-pdb.md`](docs/engines/unity-unreal-pdb.md).
Scans e assinaturas continuam sendo candidatos e nao sao promovidos a layout
confirmado.

Uma extensão somente-leitura por perfis de runtime (`GUObjectArray`,
`FNamePool`, classes e `FProperty`) está documentada como proposta na
[Spec 0012](docs/specs/0012-unreal-runtime-reflection.md). Ela não está
implementada e não altera a proveniência das tools PDB atuais.

## Licença

MIT. Consulte `LICENSE`.

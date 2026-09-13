# Spec 0005 — Início gerenciado de processo (`memory_debug_launch`)

Status: aceito · ADR: [0010](../adr/0010-managed-process-launch.md)

## Objetivo

Permitir que o MCP inicie um executável escolhido pelo operador, capturando
`stdout`/`stderr` do processo filho, para casos em que o próprio alvo
imprime informação de diagnóstico útil (como `argos_debug_target_game.exe`
faz ao iniciar). Não se destina a jogos de terceiros já em execução — ver
roadmap para a distinção de escopo.

## Contrato de domínio

```cpp
// domain
struct LaunchSpec {
    std::string executable;                    // caminho absoluto
    std::vector<std::string> arguments;         // argv; nunca string de shell
    std::optional<std::string> working_directory;
    bool capture_output{true};
};

struct OutputChunk {
    std::string stdout_text;   // UTF-8, saneado
    std::string stderr_text;
    std::uint64_t cursor{};    // offset opaco para a próxima chamada
    bool process_alive{true};
};

class LaunchedProcessSession : public ProcessSession {
public:
    [[nodiscard]] virtual Result<OutputChunk> read_output(
        std::uint64_t since_cursor,
        std::size_t max_bytes
    ) = 0;
    [[nodiscard]] virtual Result<void> terminate() = 0;
    [[nodiscard]] virtual bool owned() const noexcept = 0;  // true: MCP pode terminar
};

// acrescentar a ProcessMemoryProvider
[[nodiscard]] virtual Result<std::unique_ptr<LaunchedProcessSession>> launch(
    const LaunchSpec& spec,
    AccessMode access
) const = 0;
```

`SecurityPolicy`:

```cpp
bool allow_launch{false};                       // ARGOS_MCP_ALLOW_LAUNCH
std::vector<std::string> launch_allowed_dirs;    // ARGOS_MCP_LAUNCH_ALLOWED_DIRS (';'-separado)
std::size_t max_launched_processes{4U};
std::size_t max_captured_output_bytes{1U * 1024U * 1024U};

[[nodiscard]] domain::Result<void> authorize_launch(
    bool user_acknowledged,
    std::string_view executable_path
) const;
```

`authorize_launch` verifica: `allow_launch == true`,
`user_acknowledged == true`, `executable_path` absoluto, e — se
`launch_allowed_dirs` não vazio — prefixo dentro da allowlist. Existência e
tipo de arquivo (arquivo regular, não diretório/link simbólico para fora da
allowlist) são validados na infraestrutura antes de `CreateProcessW`.

`MemoryDebugService`:

```cpp
[[nodiscard]] domain::Result<domain::SessionInfo> launch(
    const domain::LaunchSpec& spec,
    domain::AccessMode access,
    bool authorized
);

[[nodiscard]] domain::Result<domain::OutputChunk> read_output(
    const domain::SessionId& id,
    std::uint64_t since_cursor,
    std::size_t max_bytes
) const;

// detach ganha overload/parâmetro:
[[nodiscard]] domain::Result<void> detach(
    const domain::SessionId& id,
    bool terminate = false
);
```

`detach(id, terminate=true)` retorna `access_denied` se a sessão não for
`owned`.

## Contrato de API (MCP)

`memory_debug_launch`:

```json
{
  "executable": "C:\\Users\\matheuss\\Desktop\\Sistemas\\Argos\\build\\dev\\Debug\\argos_debug_target_game.exe",
  "arguments": [],
  "access": "read_only",
  "authorized": true,
  "capture_output": true
}
```

```json
{"ok": true, "data": {"session_id": "…", "pid": 28640, "process_name": "argos_debug_target_game.exe", "access": "read_only"}}
```

`memory_debug_read_output`:

```json
{"session_id": "…", "since_cursor": 0, "max_bytes": 65536}
```

```json
{
  "ok": true,
  "data": {
    "stdout_text": "========================================\nARGOS DEBUG TARGET GAME\n...\nGameState address: 0x21142FC00\nPlayer address:    0x21142FC40\n...",
    "stderr_text": "",
    "cursor": 842,
    "process_alive": true
  }
}
```

`memory_debug_detach` (extensão): `{"session_id": "…", "terminate": true}` —
só aceito para sessões `owned`.

Erros: `access_denied` (gate desligado, path fora da allowlist, terminate
em sessão não-owned), `limit_exceeded` (processos simultâneos ou output
acima do limite), `invalid_argument` (path relativo, argv com bytes nulos).

## Segurança

- gate `ARGOS_MCP_ALLOW_LAUNCH` desligado por padrão — sem ele, a tool
  retorna `access_denied` antes de qualquer tentativa de criação de
  processo;
- `argv` é sempre um vetor; a serialização para `CreateProcessW` usa a
  rotina padrão de quoting de argumentos, nunca concatenação livre nem
  `cmd.exe`/`system()` — atende à restrição do `AGENTS.md` contra "comandos
  shell montados com entrada externa";
- pipes de `stdout`/`stderr` do filho nunca são herdados pelo `stdout` do
  MCP (`bInheritHandles` restrito só aos handles de pipe necessários) —
  preserva ADR-0001 (stdout do MCP é só protocolo);
  buffer de saída é circular e limitado por `max_captured_output_bytes`;
- `terminate` só é permitido em sessões `owned`; `attach` a um processo
  pré-existente nunca ganha essa capacidade;
- sem elevação de privilégio, sem herança de token diferente do processo do
  MCP, sem janela de console visível forçada.

## Observabilidade

Log por chamada: `executable` (caminho, não argv — argv pode conter dados
sensíveis do operador), `pid` resultante, `owned`, tamanho de saída
capturada — nunca o conteúdo de `stdout_text`/`stderr_text` em log.

## Plano de testes

- unitário: `authorize_launch` com gate desligado/ligado, path relativo,
  path fora/dentro da allowlist; `LaunchedProcessSession` falso para testar
  `read_output` com cursor incremental e `process_alive` mudando após saída
  do processo.
- segurança: teste dedicado garantindo que nenhum caractere de `argv`
  alcança um shell (ex.: `arguments: ["; calc"]` não deve abrir `calc`,
  deve ser passado literalmente como argumento único ao processo filho).
- contrato: `detach(terminate: true)` em sessão obtida por `attach` retorna
  `access_denied`; em sessão `launch`, encerra o processo e libera a
  sessão.
- regressão manual: `launch` de `argos_debug_target_game.exe`, `read_output`
  até capturar o banner completo, confirmar que os endereços impressos
  batem com o que `memory_debug_regions`/`modules` reportam para a mesma
  sessão.

## Critérios de aceite

- banner completo do alvo de teste é capturado via `read_output` sem
  polling excessivo (poucas chamadas até `cursor` estabilizar);
- gate desligado por padrão comprovado por teste automatizado, não só por
  documentação;
- threat model (`docs/threat-model/runtime-memory-debug.md`) atualizado com
  o novo ativo/ameaça antes do merge, conforme ADR-0010.

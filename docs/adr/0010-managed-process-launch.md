# ADR-0010 — Início gerenciado de processo com captura de saída

Status: aceito

## Contexto

O MCP hoje só ataca processos já em execução. Alvos de teste cooperativos
(como `argos_debug_target_game.exe`) frequentemente imprimem no próprio
`stdout` informação de diagnóstico — endereços, magic numbers, o comando de
scan recomendado — inacessível porque não há como capturar essa saída sem
ser o processo que o iniciou. Diferente de todas as tools existentes, que
apenas *leem* um processo, esta capacidade *cria* um processo — uma classe
de risco nova que o restante deste MCP nunca assume.

## Decisão

Adicionar `LaunchedProcessSession : ProcessSession` e
`ProcessMemoryProvider::launch(LaunchSpec, AccessMode)`. `LaunchSpec` recebe
caminho absoluto do executável e `argv` como vetor de strings — nunca uma
string de shell montada por concatenação. A criação de processo usa a API
nativa (`CreateProcessW` no Windows) com `argv` serializado pela rotina
padrão de quoting de argumentos, nunca via `cmd.exe`/`system()`/shell.
`stdout`/`stderr` do filho são redirecionados para pipes anônimos possuídos
pelo MCP — nunca herdados do console do MCP, preservando a regra de
ADR-0001 de que o `stdout` do MCP contém só protocolo.

Autorização é um gate novo e independente de `ARGOS_MCP_ALLOW_WRITE`:

- `ARGOS_MCP_ALLOW_LAUNCH=1` no startup (padrão: desligado);
- `authorized: true` explícito na chamada (mesmo padrão de `attach`);
- caminho deve ser absoluto e apontar para um arquivo regular existente;
- se `ARGOS_MCP_LAUNCH_ALLOWED_DIRS` estiver configurado, o caminho precisa
  estar sob um dos diretórios permitidos;
- `max_launched_processes` limita quantos processos simultâneos o MCP pode
  ter iniciado;
- `max_captured_output_bytes` limita o buffer de saída retido por sessão
  (buffer circular; excedente descarta o mais antigo).

Nova tool `memory_debug.launch` devolve `SessionInfo` (reaproveitando o
registry de sessões existente) marcada como `owned: true`. Nova tool
`memory_debug.read_output(session_id, since_cursor?, max_bytes?)` faz
polling do buffer capturado — sem streaming, mantendo o modelo
request/response do transporte atual. `memory_debug.detach` ganha parâmetro
opcional `terminate: bool = false`; `terminate: true` só é aceito quando a
sessão é `owned` — uma sessão obtida por `attach` a um processo pré-
existente nunca pode ser encerrada pelo MCP.

## Consequências

- único ponto do MCP que passa a criar processos — novo ativo no threat
  model ("processo filho criado pelo MCP") e nova ameaça ("execução de
  binário arbitrário escolhido pelo cliente"), mitigada pelo gate de
  ambiente desligado por padrão, path absoluto validado, allowlist
  opcional de diretório, ausência de shell, e limite de processos/; buffer;
- desbloqueia o cenário específico que motivou esta ADR (ler o banner de um
  alvo de teste cooperativo), mas não ajuda contra um jogo de terceiros já
  em execução — ver roadmap para a priorização relativa a outras specs;
- permanece proibido: elevação de privilégio, herança do console do MCP,
  shell intermediário, término de sessão não-`owned`.

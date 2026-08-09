# Threat model — depuração de memória em runtime

## Ativos

- memória e estado do processo alvo;
- handles de processo;
- dados potencialmente sensíveis presentes na memória;
- integridade do cliente MCP e do host local;
- processo filho criado pelo MCP (`memory_debug.launch`) e sua saída capturada
  (`stdout`/`stderr`).

## Fronteiras de confiança

1. cliente MCP → parser JSON;
2. tool handler → aplicação;
3. aplicação → provider nativo;
4. servidor → processo alvo;
5. logs `stderr` → ambiente do host.

## Ameaças e controles

### Attach não autorizado

Controles: confirmação explícita, mesmo usuário por padrão, permissões do SO e `session_id` opaco.

### Leitura excessiva ou negação de serviço

Controles: limite por leitura, limite de itens em batch, orçamento total de scan, limite de resultados e chunks de 64 KiB.

### Escrita acidental

Controles: escrita desabilitada no startup, sessão read-write explícita, confirmação fixa por chamada e limite de bytes.

### Overflow de endereço

Controles: endereços em `uint64_t`, parser hexadecimal, checagem de overflow/underflow em pointer chains e tamanhos limitados.

### Vazamento por logs

Controles: logs não registram conteúdo de memória, argumentos completos, tokens ou caminhos internos de erros nativos.

### Bypass ou uso ofensivo

Controles de escopo: não há injection, remote thread, mudança de proteção, privilege escalation, stealth, bypass de EDR/anticheat ou coleta de credenciais.

### Corrupção do protocolo

Controles: `stdout` reservado, parser rejeita chaves duplicadas e números não finitos, erros JSON-RPC tipados e testes de contrato.

### Execução de binário arbitrário escolhido pelo cliente

`memory_debug.launch` é o único ponto do MCP que cria processos em vez de
apenas lê-los — uma classe de risco nova. Controles: gate de ambiente
`ARGOS_MCP_ALLOW_LAUNCH` desligado por padrão (nega antes de qualquer
tentativa de criação de processo); `authorized: true` explícito por chamada,
mesmo padrão de `attach`; caminho do executável precisa ser absoluto e
apontar para um arquivo regular existente, validado tanto em
`SecurityPolicy::authorize_launch` (formato/allowlist) quanto na
infraestrutura antes de `CreateProcessW` (existência/tipo de arquivo);
allowlist opcional `ARGOS_MCP_LAUNCH_ALLOWED_DIRS`, comparada após
`std::filesystem::weakly_canonical` nos dois lados para impedir bypass via
`..`; `argv` é sempre um vetor de strings serializado pela rotina padrão de
quoting do Windows — nunca `cmd.exe`/`system()`/concatenação livre; pipes de
`stdout`/`stderr` do filho nunca são herdados pelo `stdout` do MCP (só a
ponta de escrita é herdável, a ponta de leitura do processo pai é marcada
`HANDLE_FLAG_INHERIT = 0` logo após `CreatePipe`), preservando a regra de
ADR-0001; texto capturado é saneado para UTF-8 válido antes de entrar em
qualquer resposta JSON; buffer de captura é limitado e circular
(`ARGOS_MCP_MAX_CAPTURED_OUTPUT_BYTES`); `ARGOS_MCP_MAX_LAUNCHED_PROCESSES`
limita processos simultâneos; `terminate` (via `memory_debug.detach`) só é
aceito para sessões `owned` (criadas por `launch`) — uma sessão obtida por
`attach` a um processo pré-existente nunca pode ser encerrada pelo MCP.
Permanece proibido: elevação de privilégio, herança de console do MCP, shell
intermediário. Este recurso não ajuda contra um processo de terceiros já em
execução — só é útil para alvos de teste/desenvolvimento que o próprio
operador controla (ver `docs/specs/0000-roadmap-introspeccao-runtime.md`).

## Riscos residuais

## Metadados de tipos e PDB

O cliente so pode consultar PDB para um modulo ja listado na sessao. DbgHelp
executa no processo MCP, com estado serializado por mutex, e retorna erro seguro
quando o PDB nao corresponde ou nao esta disponivel. O servidor nao injeta
DLL/codigo para obter reflexao de Unity ou Unreal.

- um processo do mesmo usuário pode conter dados sensíveis;
- habilitar `ARGOS_MCP_ALLOW_FOREIGN_USER` aumenta o risco operacional;
- habilitar escrita permite corrupção do processo autorizado;
- habilitar `ARGOS_MCP_ALLOW_LAUNCH` permite ao operador iniciar qualquer
  executável que o processo do MCP tenha permissão de sistema operacional
  para executar; a allowlist de diretório é um controle adicional opcional,
  não uma sandbox — o operador continua responsável por escolher
  executáveis confiáveis;
- permissões do SO e políticas corporativas continuam sendo responsabilidade do operador.

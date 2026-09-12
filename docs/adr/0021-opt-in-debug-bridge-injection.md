# ADR-0021 — Bridge de depuração injetável, opt-in e limitada a artefatos Argos

Status: aceito e implementado (bridge de carregamento; protocolo interno e
instrumentação específica de engine permanecem fora de escopo)

## Contexto

Leitura externa de memória é suficiente para valores e estruturas já
materializados no processo, mas não permite observar chamadas internas,
registrar eventos do runtime ou usar APIs de introspecção que existam somente
dentro do alvo. Esse limite ficou evidente em alvos sem PDB, RTTI ou reflexão
de engine.

Uma injeção genérica de código, shellcode ou DLL arbitrária transformaria o
MCP em um executor remoto de payloads. Isso não é um contrato de depuração
revisável nem oferece um limite de autorização útil. A capacidade deve ser
uma bridge de primeira parte, versionada e auditável, e não uma superfície
para código escolhido pelo cliente.

## Decisão

Adicionar uma capacidade `memory_debug.debug_bridge_inject` com estas regras:

1. A tool fica ausente de `tools/list` salvo quando
   `ARGOS_MCP_ALLOW_DEBUG_BRIDGE_INJECTION=1` estiver definido na inicialização
   do servidor.
2. Ela aceita somente uma DLL explicitamente permitida pelo operador em
   `ARGOS_MCP_DEBUG_BRIDGE_ALLOWED_PATHS`; a DLL precisa ser um arquivo
   absoluto, regular e canonicalizado dentro da allowlist. A primeira bridge
   distribuída é `argos_debug_bridge.dll`.
3. A chamada exige uma sessão existente, do mesmo usuário por padrão, e uma
   confirmação explícita `authorized: true`. A sessão não precisa habilitar
   `memory_debug.write`: injeção é uma capacidade diferente, nunca implícita
   em escrita de bytes.
4. No Windows, a infraestrutura executa somente o carregamento de uma DLL
   validada pelo loader do sistema. Detalhes Win32, handles e conversões
   UTF-8/UTF-16 ficam em `infrastructure`; domínio e aplicação veem apenas
   `DebugBridgeSpec` e `InjectedDebugBridge`.
5. A resposta revela PID, nome canônico da bridge e base carregada; não expõe
   handles, bytes de memória, caminhos externos completos ou erros Win32
   detalhados. Logs estruturados em `stderr` registram evento, PID e resultado,
   sem payload, argumento ou conteúdo do alvo.
6. A primeira entrega não instala hooks, não chama exports arbitrários e não
   cria um interpretador dentro do alvo. Ela estabelece somente o ciclo de
   vida de carregamento e a prova de presença da bridge. Comandos de
   observação posteriores exigem ADR, protocolo versionado e testes próprios.

O contrato é modelado na porta `ProcessSession`: plataformas que não o
suportam retornam `unsupported`. Não há fallback para escrever código na
memória ou alterar proteções de página.

## Consequências

- alvos autorizados passam a poder hospedar instrumentação Argos de primeira
  parte, começando por uma bridge sem comandos;
- o servidor ganha uma operação de alto impacto, com gate independente,
  allowlist e auditoria;
- a capacidade não suporta DLL de terceiros, shellcode, loader customizado,
  evasão de anticheat/EDR, elevação de privilégio nem processos de outro
  usuário;
- builds não-Windows permanecem funcionalmente inalteradas e retornam
  `unsupported` para a operação;
- injetar a bridge não garante que um jogo revele tipos/XP: o valor vem quando
  uma extensão de bridge específica do engine for projetada e validada.

## Verificação

- testes de política: gate desligado, confirmação ausente, caminho relativo,
  fora da allowlist e caminho com `..` devem falhar antes da infraestrutura;
- testes de aplicação usam `ProcessSession` falso e verificam que sessão e
  resultado são preservados;
- testes de contrato garantem que a tool não é anunciada com o gate desligado;
- teste Windows usa apenas `argos_debug_target_game` e a bridge compilada no
  próprio repositório; nunca um processo externo;
- build MSVC e testes normais precisam passar antes de a ADR mudar para
  implementado.

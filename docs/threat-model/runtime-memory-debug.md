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

Controles: limite por leitura, limite de itens em batch, orçamento total de scan, limite de resultados e chunks de 64 KiB. `scan_pointer_chains` reutiliza o mesmo orçamento de bytes compartilhado e adiciona tetos de profundidade e fan-out (`ARGOS_MCP_MAX_POINTER_CHAIN_DEPTH`/`ARGOS_MCP_MAX_POINTER_CHAIN_FANOUT`). A fronteira inteira é comparada em uma única passagem por profundidade, limitando o I/O a `O(max_depth)` passagens; `visited` previne ciclos.

`memory_debug.regions` aplica filtro e paginação no servidor, e `memory_debug.address_space_summary` devolve apenas agregados de tamanho e contagem. Ambos **reduzem** o volume trafegado: substituem o despejo integral da lista de regiões — dezenas de milhares de entradas num alvo real — por um recorte ou por um resumo de tamanho constante. Nenhum dos dois expõe conteúdo de memória, apenas metadados de mapeamento que `regions` já expunha.

O bloco `coverage` de `scan_first` reporta apenas contagens de bytes e regiões varridas, sem conteúdo. Ele existe para evitar uma falha de interpretação com consequência prática: sem ele, um resultado vazio por orçamento esgotado é indistinguível de "o valor não existe", o que leva o cliente a repetir varreduras desnecessárias — custo que este mesmo controle de DoS pretende limitar.

### Escrita acidental

Controles: escrita desabilitada no startup, sessão read-write explícita, confirmação fixa por chamada e limite de bytes.

### Overflow de endereço

Controles: endereços em `uint64_t`, parser hexadecimal, checagem de overflow/underflow em pointer chains e tamanhos limitados.

### Vazamento por logs

Controles: logs não registram conteúdo de memória, argumentos completos, tokens ou caminhos internos de erros nativos.

### Bypass ou uso ofensivo

Controles de escopo: não há injection, remote thread, mudança de proteção, privilege escalation, stealth, bypass de EDR/anticheat ou coleta de credenciais.

### Corrupção do protocolo

Controles: `stdout` reservado; cada frame é drenado e rejeitado acima de 8 MiB antes de crescer sem limite; parser limita nesting a 128 e o DOM a 65.536 nós, rejeita chaves duplicadas e nunca serializa números não finitos; erros JSON-RPC são tipados. Cancelamento é linearizado com a conclusão e suprime qualquer resposta tardia com o ID cancelado. Testes de contrato verificam ressincronização após frame excessivo e as duas eras do protocolo.

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

## Inspeção derivada de endereço

`memory_debug.inspect_address` é somente leitura e substitui um fluxo que hoje
transfere bytes crus por metadados derivados pequenos — uma **redução** de
exposição, não um aumento. Ela lê apenas regiões marcadas como legíveis, nunca
dereferencia uma função da possível vtable e valida `address + size`, a
subtração do lookbehind, `módulo + RVA` e `vtable + K * pointer_size` antes de
qualquer I/O. Todo limite (janela, bases examinadas, probes, entradas,
candidatos, evidências, proveniências, referências) é aplicado antes de alocar
ou ler, e a memória auxiliar é proporcional a esses limites, não ao tamanho do
processo.

O risco específico é epistemológico: uma heurística apresentada como fato leva o
operador a escrever no lugar errado. O contrato responde com
`classification: "probable"` obrigatório, confiança/evidência/proveniência
auditáveis, múltiplos candidatos preservados em vez de uma verdade escolhida em
silêncio, e ausência representada como `null`/vazio em vez de sentinela.

O `resume_token` é assinado por uma chave aleatória do processo servidor e
vinculado a sessão, alvo, largura de ponteiro e filtros. Ele não atravessa
sessões nem consultas, e um servidor reiniciado recusa continuações antigas em
vez de retomar uma varredura sobre um espaço de endereçamento que já não existe.
Endereços, bytes, nomes de módulo/região, `session_id`, cursores e tokens não
entram no log.

## Reflexão Unreal em runtime

Esta capacidade lê estruturas de reflexão que o próprio runtime mantém. Ela não
chama `StaticClass`/`ProcessEvent` nem qualquer função do alvo, não injeta
DLL/código, não cria thread remota, não altera proteção e não escreve. Ela não
contorna nem descriptografa proteção/ofuscação, e não percorre arquivos nem
módulos indicados por path arbitrário — apenas módulos da sessão autorizada.

Três controles server-side, todos aplicados antes de I/O ou alocação:

- `ARGOS_MCP_ENABLE_UNREAL_RUNTIME=0` por padrão. Com o gate desligado, as tools
  nem aparecem em `tools/list`;
- allowlist de `profile_id` (`ARGOS_MCP_UNREAL_PROFILES`). Allowlist vazia
  significa **nenhum** perfil habilitado, não todos;
- `ARGOS_MCP_ENABLE_UNREAL_AUTO_DISCOVERY=0`, independente do gate geral.

Uma requisição nunca liga um gate. O parser trata a memória do alvo como
hostil: contagens do alvo são validadas antes de dimensionar qualquer loop ou
leitura; toda lista encadeada tem detecção de ciclo, limite de nós e deadline;
ponteiros precisam estar alinhados e cair em região legível; `offset +
element_size * array_dim` é verificado contra overflow; short read é tratado
como instabilidade, nunca como bytes zerados.

O aumento de exposição é o catálogo em si: nomes de classes, objetos e
propriedades do processo autorizado passam a caber numa resposta. Isso é
mitigado por paginação, quotas por sessão e globais, teto de bytes retidos, TTL
de contexto, e pela regra de que **valores de instância ficam fora**: ler um
campo continua exigindo uma tool de leitura explícita sob a policy normal. Um
`runtime_id` não é capability bearer — toda query exige `session_id` +
`runtime_id`, e um dono divergente recebe `not_found`. Nenhuma assinatura, nome,
endereço, propriedade ou byte do processo entra no log.

Nomes lidos do alvo são sanitizados para ASCII imprimível antes de entrarem no
protocolo, para que um nome hostil não injete caracteres de controle nem
sequências UTF-8 inválidas no fluxo JSON-RPC.

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
- candidatos de `inspect_address` continuam sendo heurística: falsos positivos
  são possíveis e explicitados por `probable`/`confidence`/`evidence`, não
  eliminados;
- snapshots de memória, regiões e módulos não são atômicos; `sampled_at_ms`,
  `limitations` e `snapshot_status` tornam essa condição visível em vez de
  removê-la;
- habilitar a reflexão Unreal expõe nomes de classes, objetos e propriedades do
  processo autorizado ao cliente MCP;
- um perfil de layout habilitado para uma build incompatível falha de modo
  seguro pelas invariantes, mas habilitar perfis é decisão do operador e novos
  perfis exigem fixtures e revisão de segurança antes de serem oferecidos;
- permissões do SO e políticas corporativas continuam sendo responsabilidade do operador.

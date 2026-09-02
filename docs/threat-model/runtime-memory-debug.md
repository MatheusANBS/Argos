# Threat model — depuração de memória em runtime

## Ativos

- memória e estado do processo alvo;
- handles de processo;
- dados potencialmente sensíveis presentes na memória;
- integridade do cliente MCP e do host local;
- processo filho criado pelo MCP (`memory_debug.launch`) e sua saída capturada
  (`stdout`/`stderr`);
- jobs de análise assíncronos (`AnalysisJobManager`) e os resultados/progresso
  retidos em memória durante seu TTL (Spec 0008 — **implementado**; jobs de
  `pointer_index`/`unreal_runtime` das Specs 0010/0012 permanecem propostos);
- candidatos de scan importados pelo cliente e sessões multipadrão
  materializadas (Spec 0009 — proposto);
- índice invertido de ponteiros, em memória e, quando habilitado pelo
  operador, em disco (Spec 0010 — proposto);
- evidência derivada de endereço — candidatos de objeto/vtable e referências
  correlacionadas (Spec 0011 — proposto);
- contexto de reflexão Unreal (`runtime_id`) e os catálogos de
  classes/propriedades/objetos derivados de `GUObjectArray`/`FNamePool`
  (Spec 0012 — proposto);
- nomes de classe, propriedade e objeto extraídos do processo-alvo, que
  passam a trafegar em respostas MCP em vez de apenas endereços e metadados
  de mapeamento (Spec 0011, 0012 — proposto).

## Fronteiras de confiança

1. cliente MCP → parser JSON;
2. tool handler → aplicação;
3. aplicação → provider nativo;
4. servidor → processo alvo;
5. logs `stderr` → ambiente do host;
6. cliente MCP → lista de candidatos importados (`scan_import`, Spec 0009 —
   proposto) — primeira vez que o servidor aceita endereços arbitrários do
   cliente como entrada de um pipeline com estado, em vez de apenas
   parâmetros de busca;
7. processo-alvo → parser estrutural (Spec 0012 — proposto) — primeira vez
   que o servidor decodifica counts, capacities, ponteiros de listas
   encadeadas e comprimentos de nome como campos que dirigem a própria
   leitura seguinte, em vez de apenas copiar bytes já lidos;
8. servidor → filesystem de persistência (Spec 0010 — proposto, disco
   opt-in) — primeira vez que uma capacidade de scan grava artefato derivado
   em disco;
9. job assíncrono → sessão de depuração (Spec 0008 — **implementado**) —
   trabalho em background passa a existir fora do ciclo de vida de uma única
   chamada MCP, com concorrência real entre sessões diferentes. Mitigado por
   fila/pool limitados, TTL, cancelamento cooperativo e destruição
   determinística em `detach`/shutdown; retomada por `resume_token` não é
   implementada nesta versão (ver Spec 0008), o que remove a superfície de
   ataque associada a fingerprint de região e admissão CAS até que seja
   implementada.

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

## Ameaças e controles — capacidades propostas (Specs 0008–0012)

Esta seção foi escrita como gate textual pré-implementação (exigido pela
ADR-0012 antes da Spec 0008, e pelas ADR-0017/0018/0019 antes das Specs
0009–0012). **As Specs 0008, 0011 e 0012 saíram desse estado:**
`AnalysisJobManager` e as cinco tools de job (Spec 0008) estão implementadas
e expostas em `README.md`, assim como `memory_debug.inspect_address` (Spec
0011) e as tools `memory_debug.unreal_runtime_*` (Spec 0012) — ver as seções
"Inspeção derivada de endereço" e "Reflexão Unreal em runtime" abaixo para a
descrição das mitigações efetivamente implementadas. As análises das
subseções "Spec 0008", "Spec 0011" e "Spec 0012" abaixo permanecem válidas
como descrição das mitigações reais — apenas deixaram de ser hipotéticas. A
exceção registrada é `resume_token` (Spec 0008): não implementado nesta
versão, então a superfície associada (fingerprint de região, admissão CAS,
estado de overlap persistido) descrita nas subseções abaixo continua sendo
apenas uma análise antecipada de um ponto de extensão futuro, não uma ameaça
contra código existente. As Specs 0009 e 0010 continuam **integralmente não
implementadas**; nenhuma delas está exposta como tool MCP nem consta na
tabela do `README.md`.

### Exaustão de recursos por jobs concorrentes (Spec 0008)

Vetor: hoje o servidor serializa uma tool de execução longa por vez; a
Spec 0008 introduz um pool fixo de workers `std::jthread` que processam jobs
de múltiplas sessões simultaneamente, cada um retendo um snapshot de
resultado em memória durante o TTL.

Impacto: um cliente que abre várias sessões (ou várias chamadas
`scan_start`) pode reter, ao mesmo tempo, N snapshots de resultado, N
entradas de fila e N workers ocupados — pico de RAM e I/O do processo MCP e
do alvo muito acima do que a serialização atual permite.

Controle especificado: fila global e por sessão limitadas e FIFO; quota por
sessão contra "encher a fila"; conjunto fixo de workers globais; hard caps
independentes de bytes/deadline/itens de resultado/memória retida/TTL por
job; admissão falha antes de alocar buffers grandes ou ler o alvo (Spec 0008,
"Backpressure e limites"). Um scan síncrono e jobs assíncronos compartilham o
mesmo slot de execução longa por sessão — no máximo um job `running` por
sessão por padrão, com `invalid_state`/`analysis_job_active` caso contrário.

Lacuna: nenhum valor numérico desses hard caps é fixado na spec — tamanho da
fila, número de workers, TTL de resultado e TTL de tombstone ficam como
"limites rígidos definidos no servidor" sem default proposto (diferente do
threat model atual para as tools já implementadas, que cita números
concretos como chunks de 64 KiB e os env vars de profundidade/fan-out de
`scan_pointer_chains`). Sem números concretos e testados sob múltiplas
sessões, este item de DoS não pode ser considerado fechado.

Lacuna adicional — apuração de fairness entre `AnalysisJobKind`: `scan`,
`pointer_index` e `unreal_runtime` compartilham o mesmo `AnalysisJobManager`,
a mesma fila e o mesmo pool de workers (Spec 0008, 0010, 0012). A Spec 0008
define quota por sessão, mas não define reserva ou prioridade por tipo de
job; uma sessão que enfileira builds de índice de ponteiros caros pode
esgotar os workers globais disponíveis para jobs de scan de outra sessão,
mesmo respeitando a quota por sessão. O plano de testes da Spec 0008 pede
"backpressure sob múltiplas sessões sem starvation permanente", mas isso
cobre starvation entre sessões, não entre tipos de job dentro da mesma fila
global.

### `scan_import` fora do modelo de backpressure de jobs (Spec 0009)

Vetor: `scan_import` (Spec 0009) é uma chamada de aplicação síncrona — não
consta entre as operações que a Spec 0008 converte em job nem existe como
`AnalysisJobKind`. Ela pode ler até 262.144 endereços (teto rígido da tabela
de limites da Spec 0009) numa única chamada, agrupando leituras dentro de
`max_read_bytes`.

Impacto: por ser síncrona, a spec não declara se `scan_import` conta contra
a regra "no máximo um scan longo `running` por sessão" que a Spec 0008 define
para operações que passam pelo `AnalysisJobManager`. Se não contar, um
cliente pode chamar `scan_import` repetidamente, em paralelo a um job
assíncrono já ocupando a quota da sessão, multiplicando I/O nativo por um
canal que fica fora da fila e das quotas centrais da Spec 0008.

Controle especificado: apenas limites de tamanho da própria chamada
(endereços por `scan_import`, itens de erro retornados) e a política de
leitura (`reject_all`/`skip_unreadable`). Nada relaciona `scan_import` ao
slot de execução longa por sessão nem define uma taxa máxima de chamadas por
sessão/tempo.

Lacuna: falta declarar explicitamente se `scan_import` consome o mesmo
slot/quota de execução longa que scans síncronos e jobs assíncronos, e qual
limite de frequência impede que ela vire um canal de leitura não regulado
pelo mecanismo de backpressure central da Spec 0008.

### Entrada hostil do cliente MCP — endereços e padrões (Spec 0009)

Vetor: `scan_import` aceita uma lista de endereços arbitrários; `scan_start`
com `operation: "multi_pattern"` aceita até 256 padrões e listas de bytes
definidos pelo cliente.

Impacto potencial sem controle: um endereço fora do espaço representável, ou
cujo `address + scan_value_size(type)` transborda, corromperia o cálculo de
faixa de leitura; um padrão vazio, hex inválido ou alinhamento que não é
potência de dois poderia ser interpretado incorretamente pelo matcher
multipadrão.

Controle especificado: overflow de `address + value_size` é verificado antes
da leitura (Spec 0009, "Contratos de domínio"); toda entrada é validada
antes de qualquer I/O — IDs duplicados, padrão vazio, hex inválido,
alinhamento que não é potência de dois, literal fora da faixa do tipo e soma
de bytes acima do limite retornam `invalid_argument`/`limit_exceeded`
(Spec 0009, "Limites e segurança"); endereço zero só é aceito quando a
plataforma realmente o expõe como região legível; a soma de todos os IDs
explícitos e derivados (`value_type: "auto"`) é validada antes de I/O,
inclusive colisão entre `<id>` e `<outro-id>:<type>`.

Este vetor está bem coberto pela spec; a lacuna real deste par de tools é a
de backpressure (item anterior), não a de validação de entrada.

### Persistência do índice de ponteiros — build e memória (Spec 0010)

Vetor: o build do índice lê todo o mapa elegível uma vez, ordena e retém
arestas em memória privada do job antes de publicar.

Impacto: pico de RAM durante a ordenação de um alvo com dezenas de milhões
de ponteiros plausíveis — risco que a própria ADR-0018 reconhece ("o vetor
ordenado favorece range query e formato simples, mas exige pico de RAM
durante sort e quotas conservadoras").

Controle especificado: limites de bytes, arestas e memória retida aplicados
durante a construção, antes da ordenação (Spec 0010, "Seleção de arestas",
item 5); publicação COW sob lock curto; cancelamento ou falha nunca publica
índice parcial, exceto quando `allow_partial: true` for pedido explicitamente
— opção que, mesmo assim, permanece indisponível para `storage: "disk"`.

Lacuna: como em Spec 0008 e 0012, os valores de quota (arestas máximas por
índice, bytes de RAM por índice/sessão/servidor, TTL mínimo/máximo) não são
fixados — a própria spec declara: "Defaults e hard caps precisam ser
definidos a partir do benchmark antes da aceitação da implementação"
(Spec 0010, "Persistência").

### Persistência em disco — path, permissões e arquivo hostil (Spec 0010)

Vetor: `storage: "disk"` grava um artefato derivado do índice num diretório
configurado pelo operador; o loader lê esse artefato (potencialmente de uma
execução anterior do servidor) de volta.

Invariante e campo: o nome do arquivo deriva exclusivamente de `index_id`
opaco — o cliente nunca envia path ou filename (Spec 0010, "Disco somente
opt-in"); o diretório é canonicalizado pelo servidor e symlink/reparse point
não são aceitos; ACL/DACL owner-only no Windows, ou diretório `0700`/arquivo
`0600` no POSIX, com falha fechada se a permissão não puder ser aplicada.

Controle especificado para arquivo hostil: o loader valida versão, flags,
larguras, contagens, multiplicações, offsets de seção, tamanho exato do
arquivo, ordenação e checksum **antes** de qualquer alocação proporcional ao
conteúdo (Spec 0010, "Formato v1 proposto"). Isso cobre integer overflow
dirigido pelo header e alocação não proporcional a um count hostil —
exatamente o padrão de invariante que este threat model já exige em outros
pontos.

Lacuna reconhecida pela própria spec, e que este documento formaliza como
risco: "CRC32C detecta corrupção acidental; não é MAC e não autentica um
atacante com acesso de escrita ao diretório" (Spec 0010, "Formato v1
proposto"). A integridade do artefato depende inteiramente da ACL do
sistema operacional. Se `ARGOS_MCP_ALLOW_FOREIGN_USER` estiver habilitado
(risco já registrado abaixo em "Riscos residuais" para o attach) e o mesmo
diretório de índice for compartilhável entre usuários, um segundo usuário
local com acesso de escrita ao diretório configurado pode plantar um índice
sintaticamente válido — com checksum correto — contendo arestas fabricadas
dentro dos limites de tamanho aceitos. A revalidação `live_confirmed`
(Spec 0010, "Revalidação ao vivo") impede que uma cadeia fabricada seja
devolvida como confirmada sem reexecutá-la contra a sessão viva, mas a spec
não avalia o custo de negação de serviço de um índice plantado com milhões
de arestas falsas: cada query subsequente gastaria seu orçamento de
revalidação tentando candidatos fabricados antes de concluir que nenhum é
válido. Não há um limite de "taxa de falha de revalidação" que interrompa
uma consulta cujo índice parece estruturalmente válido mas nunca produz
`live_confirmed`.

### Confusão de identidade — PID reuse, ASLR, restart (Spec 0010, 0012)

Vetor: `PointerIndexId` (Spec 0010) e `runtime_id` (Spec 0012) referenciam
estado derivado de um processo específico; ambos podem, em tese, sobreviver
— em memória ou disco — a eventos que invalidam essa referência.

Invariante e campo: `ProcessFingerprint` (Spec 0010) exige igualdade
simultânea de PID, `creation_time`, hash do conjunto de módulos e hash do
mapa elegível — "PID sozinho é insuficiente porque pode ser reutilizado"
(Spec 0010, "Identidade, staleness e ASLR"); qualquer divergência retorna
`invalid_state`/`stale_index`, nunca reaproveita silenciosamente. `runtime_id`
(Spec 0012) usa a mesma `ProcessIdentity` da sessão e nunca é aceito fora da
sessão que o originou — `session_id` + `runtime_id` são sempre exigidos
juntos, e owner divergente retorna `not_found` sem revelar o contexto; este
controle é mais forte que o de disco porque `runtime_id` não sobrevive ao
processo MCP.

Lacuna: a spec exige que o provider nativo forneça `creation_time` "em
representação estável para comparação na mesma plataforma" (Spec 0010,
"Modelo de dados"), mas não define uma resolução mínima aceitável. Se a
plataforma só oferecer timestamps de baixa granularidade, dois processos de
vida curta com o mesmo PID reciclado rapidamente poderiam, em tese, colidir
também em `creation_time`, esvaziando a defesa contra PID reuse que a
própria spec elege como o controle central desse risco. A spec não define
um requisito mínimo de granularidade nem uma fonte adicional de entropia
(por exemplo, um contador monotônico interno do MCP) para o caso em que o
SO não oferecer resolução suficiente.

### Parsing de estruturas hostis controladas pelo processo-alvo (Spec 0012)

Este é o vetor qualitativamente novo apontado pela ADR-0019: até hoje o
servidor apenas copia bytes lidos do alvo para a resposta; a partir da
Spec 0012, ele passa a interpretar counts, capacities, ponteiros de listas
encadeadas e comprimentos de nome como campos estruturados que dirigem a
própria leitura seguinte — o processo-alvo, não apenas o cliente MCP, se
torna uma fonte de entrada hostil relevante para correção do parser.

Controles já especificados por invariante:

- **Integer overflow em aritmética de offset**: `offset + element_size *
  array_dim` (parsing de `FProperty`) deve ser checked e coerente com o
  tamanho refletido quando conhecido (Spec 0012, "Invariantes mínimas");
  toda soma endereço+tamanho no domínio usa helpers checked ("Arquitetura").
- **Counts/capacities hostis dirigindo alocação**: `num_elements <=
  max_elements <= hard_limit` é verificado antes de qualquer alocação
  proporcional — "Counts do alvo nunca causam `reserve` antes de serem
  validados contra esses limites" (Spec 0012, "Limites e segurança"). Isso
  fecha o caso de um count de `GUObjectArray` dirigindo `reserve` de
  terabytes.
- **Loops de lista encadeada** (`SuperStruct`, cadeia de `FProperty`):
  devem ser acíclicos dentro de um limite de profundidade — `max_super_depth:
  64`, `nós numa cadeia de properties: 4.096` — e um ciclo detectado é
  rejeitado, não seguido indefinidamente (Spec 0012, tabela de limites e
  "Invariantes mínimas").
- **Leitura fora de limites / ponteiro desalinhado**: todo ponteiro deve
  estar alinhado quando o ABI exige e cair em região legível antes de ser
  seguido; short-read é evidência de instabilidade, nunca bytes zerados
  (Spec 0012, "Limites e segurança").
- **Confusão entre perfis**: um perfil `UProperty` (legado) e um perfil
  `FField/FProperty` (moderno) não compartilham offsets por fallback; perfil
  desconhecido ou incompatível é rejeitado antes de tentar interpretar bytes
  com offsets de outro perfil (Spec 0012, "Perfil de layout"; teste
  explícito no plano de testes).
- **Memória mutando durante o parse**: cada página de `GUObjectArray` é
  lida, processada e relida antes de ser aceita; divergência entre a
  primeira e a segunda leitura do mesmo tuple `(object_index, serial,
  object_pointer)` — não apenas do count — força retry (até 2 tentativas por
  padrão) e depois `failed/unstable_snapshot`, descartando o draft inteiro
  (Spec 0012, "Consistência de snapshot"). Isso fecha especificamente o caso
  de um slot reciclado com a mesma contagem total.

Duas lacunas não fechadas pela spec:

**Lacuna 1 — sanitização de nomes decodificados antes do JSON.**
`FNamePool`, nomes de classe e de propriedade são decodificados de bytes do
alvo e devolvidos como string (`object_name`, `class_name`, `name` em
`UnrealPropertyInfo`/`UnrealClassSummary`). A Spec 0012 exige que o
comprimento/índice caibam no pool e respeitem "comprimento e UTF-8/UTF-16
previstos pelo perfil" (Spec 0012, "Invariantes mínimas"), mas não declara o
que fazer com uma sequência de bytes que satisfaz o comprimento declarado
porém não é UTF-8/UTF-16 válido — por exemplo, memória corrompida ou um
processo-alvo adversarial que grava lixo binário exatamente no formato de
comprimento esperado. O threat model atual já exige, para
`memory_debug.launch`, que "texto capturado é saneado para UTF-8 válido
antes de entrar em qualquer resposta JSON"; a Spec 0012 não repete essa
exigência para nomes Unreal. Sem ela, bytes arbitrários do alvo poderiam
propagar para o payload JSON.

**Lacuna 2 — plausibilidade da detecção por assinatura em modo `auto`.**
`signature_candidate` (modo `auto`) localiza raízes por scan multipadrão em
módulos autorizados; a spec limita a promoção de confiança
("`signature_candidate` não atinge `high` sem uma segunda evidência
independente e validação integral", "Invariantes mínimas"), mas não elimina
o cenário em que um processo-alvo adversarial constrói deliberadamente bytes
que (a) casam a assinatura de `GUObjectArray`/`FNamePool` e (b) também
satisfazem todas as invariantes estruturais obrigatórias (counts dentro do
limite, ponteiros alinhados e legíveis, listas acíclicas) sem serem, de
fato, as estruturas reais do engine. O resultado seria `confidence: medium`
com nomes de classe/propriedade fabricados que *parecem* estruturalmente
válidos. A spec mitiga isso apenas com o rótulo de confiança, não com um
limite adicional de plausibilidade (por exemplo, cross-check contra um
fingerprint de build conhecida). O pior caso continua sendo confundir o
operador com metadados plausíveis, não comprometer memória ou segurança do
host — mas o limite da garantia deve ficar explícito, não implícito.

### Vazamento de dados de reflexão em logs e respostas (Spec 0011, 0012)

Vetor: pela primeira vez, respostas MCP carregam nomes de classe, nomes de
propriedade e evidência correlacionada ao conteúdo do jogo, não apenas
endereços e metadados de mapeamento.

Controle especificado: as duas specs têm uma lista fechada e simétrica de
"nunca logar". Spec 0011 proíbe endereço alvo, ponteiros de
objeto/vtable/função, referências, bytes de memória, nomes/paths de
módulo/região, IDs opacos e argumentos completos. Spec 0012 proíbe
signature, nome, endereço, propriedade ou byte do processo em log, e
especifica que `unreal_runtime_validation_failed` carrega "código de
invariante, nunca endereço ou bytes". Em ambas, `stderr` só recebe IDs
opacos, contagens agregadas, fase e motivo de término tipado — nunca o
conteúdo (nome de classe, valor, endereço) que motivou o resultado.

Este controle está bem especificado; a lacuna aqui é de responsabilidade de
integração, não de design do servidor: como a resposta ao **cliente** (não
o log do Argos) agora inclui nomes de classe e propriedade do jogo, um
cliente MCP que ecoe essa resposta para seu próprio log — fora do controle
do Argos — reintroduziria o vazamento numa camada que este documento não
cobre. Isso deve ficar registrado como responsabilidade explícita do
operador/integrador, análoga ao risco residual já existente de dados
sensíveis presentes em processos do mesmo usuário.

### Confiança e proveniência — heurística promovida a fato (Spec 0011, 0012; ADR-0005)

Vetor: `inspect_address` (Spec 0011) e a reflexão Unreal (Spec 0012) ambas
produzem evidência derivada de heurística (vtable provável, candidato por
assinatura) que um cliente ou agente automatizado poderia, por engano de
interpretação, tratar como fato confirmado.

Controle especificado: Spec 0011 exige `classification: "probable"` em todo
candidato, mesmo com `confidence: "high"`, e proíbe inventar nome de
classe/tipo/símbolo (ADR-0013, "Consequências"). Spec 0012 só permite
`confidence: "high"` quando "perfil, identidade da build, raízes e
estruturas percorridas foram integralmente validados" e nunca promove uma
evidência a fato "apenas porque um nome legível foi encontrado" (ADR-0019,
"Decisão"). Isso é consistente com a proibição que a ADR-0005 já impõe para
scans genéricos: "O MCP não inventa offsets de `UClass`, `FProperty` ou
objetos a partir de scans genéricos".

Verificação de coerência com ADR-0005: a Spec 0012 **não** viola essa
proibição, porque os offsets de `FProperty` relatados pela reflexão runtime
não vêm de um scan de assinatura genérico — vêm de percorrer estruturas de
reflexão do próprio engine (listas de `FField`/`FProperty` com nome, tamanho
e offset internos), validadas estruturalmente contra as invariantes acima.
A ADR-0019 declara explicitamente que "estende, quando aceita e
implementada, ADR-0005" e "não muda o significado das tools atuais" — o
caminho PDB continua sendo o único a produzir `source: pdb:dbghelp` com
`confidence: high` garantida por símbolo. Nenhuma contradição encontrada.

O ponto que precisa ficar auditável, e que hoje só está descrito em prosa: a
única fonte de `confidence: high` sem PDB é uma raiz `build_profile` ou
`explicit_*` com todas as invariantes obrigatórias validadas; uma raiz
`signature_candidate` nunca deve, em nenhuma versão futura, alcançar `high`
sem uma segunda fonte independente. Isso deveria ser um invariante coberto
por teste de contrato (rejeição de `signature_candidate` + `confidence:
high` como combinação impossível, análogo ao teste já pedido para
`AnalysisStopReason` × `AnalysisJobKind` na Spec 0008), não apenas uma regra
descrita em texto.

## Lacunas identificadas antes da implementação

Lista consolidada dos itens acima que **não têm mitigação suficiente
especificada** nas Specs 0008–0012. Nenhum destes deveria ser tratado como
resolvido só porque a spec correspondente existe:

1. **Backpressure sem números concretos** (Spec 0008, 0010, 0012): tamanho de
   fila, contagem de workers, TTL de resultado/tombstone, arestas/bytes
   máximos de índice e slots/objetos máximos por job Unreal não têm default
   proposto — todas as specs adiam isso para "benchmark antes da aceitação".
2. **`scan_import` fora do slot de execução longa** (Spec 0009): não está
   especificado se conta contra a mesma quota por sessão que scans
   síncronos e jobs assíncronos, nem há limite de frequência de chamada.
3. **Fairness entre `AnalysisJobKind`** (Spec 0008, 0010, 0012): scan,
   pointer-index e Unreal runtime compartilham fila e pool de workers sem
   reserva ou prioridade por tipo — starvation entre tipos de job não é
   coberta pelos testes de fairness propostos, que só cobrem starvation
   entre sessões.
4. **Índice em disco sem autenticação** (Spec 0010): CRC32C não é MAC; a
   integridade depende inteiramente da ACL do sistema operacional. Não há
   limite de custo de revalidação para um índice estruturalmente válido mas
   fabricado (nenhuma cadeia jamais confirma `live_confirmed`).
5. **Resolução de `creation_time` para desambiguar PID reuse** (Spec 0010):
   nenhuma granularidade mínima é exigida da plataforma; se o SO oferecer
   baixa resolução, a defesa central contra PID reuse se enfraquece sem que
   a spec preveja fallback.
6. **Sanitização de nomes Unreal decodificados** (Spec 0012): ao contrário
   de `memory_debug.launch`, a spec não exige explicitamente saneamento
   para UTF-8 válido de `object_name`/`class_name`/nomes de propriedade
   antes de entrarem na resposta JSON.
7. **Teste de contrato ausente para `signature_candidate` × `confidence:
   high`** (Spec 0012): a proibição existe em prosa, mas não é declarada
   como combinação estruturalmente impossível no serializer, ao contrário
   do padrão já usado para `AnalysisStopReason` × `AnalysisJobKind`.

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

Perfis de build registrados pelo operador não são aceitos do cliente MCP. O
parser limita a configuração a 32 KiB/64 registros e assinaturas de 8–64 bytes;
um registro só corresponde quando nome, tamanho e bytes no RVA configurado
batem exatamente. Mismatch, leitura curta e ambiguidade falham fechados. Os
RVAs resultantes ainda passam por bounds/overflow e por todas as invariantes do
runtime antes da publicação. Bytes esperados ou observados nunca entram em log.

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
- (proposto — Spec 0010) habilitar `storage: "disk"` para o índice de
  ponteiros cria retenção local de dados derivados do layout do processo
  além do encerramento da sessão, até TTL ou `pointer_index_delete`; a
  combinação com `ARGOS_MCP_ALLOW_FOREIGN_USER` amplia o risco existente de
  attach a processo de outro usuário, porque o artefato em disco passa a
  reter, sob a conta do operador do MCP, evidência derivada da memória de um
  processo que pertence a outra identidade de SO;
- (proposto — Spec 0008–0012) os hard caps de fila, workers, TTL, arestas e
  slots dessas capacidades ainda não têm valor numérico definido nas specs;
  a implementação não deve ser aceita com os limites deixados apenas como
  "definidos pelo servidor" em prosa — ver "Lacunas identificadas antes da
  implementação" acima;
- (proposto — Spec 0012) `signature_candidate` em modo `auto` é heurística
  rotulada, não prova; um processo-alvo adversarial ou corrompido pode, em
  tese, produzir bytes que satisfazem as invariantes estruturais obrigatórias
  sem serem as estruturas reais do engine, resultando em `confidence: medium`
  com nomes fabricados porém plausíveis — o pior caso é confundir o operador,
  não comprometer memória ou segurança do host.

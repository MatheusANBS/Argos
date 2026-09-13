# Spec 0008 — Operações assíncronas de scan

Status: aceito · ADR: [0012](../adr/0012-async-scan-progress-resumption.md)

## Objetivo

Permitir que scans grandes percorram todo o espaço elegível sem manter uma
chamada MCP aberta durante toda a operação e sem obrigar o cliente a calcular
janelas manualmente. O cliente inicia um job, consulta progresso, pagina o
resultado terminal e libera o estado retido de forma explícita.

A proposta materializa os itens A1 e A2 do
[roadmap de eficiência em alvo real](0007-roadmap-eficiencia-agente.md). Ela
preserva o ownership de processo da [ADR-0002](../adr/0002-explicit-debug-sessions.md),
o ownership de candidatos da [ADR-0009](../adr/0009-value-diff-scan-sessions.md)
e os envelopes das duas eras MCP definidos na
[ADR-0016](../adr/0016-mcp-dual-era-2026.md).

## Nota de implementação

`AnalysisJobManager` e as cinco tools (`scan_start`, `job_status`,
`job_results`, `job_cancel`, `job_release`) estão implementados e cobertos por
teste para os seis operações elegíveis. O lifecycle completo (estados,
progresso monotônico, cancelamento cooperativo, backpressure, TTL de
resultado e de tombstone, paginação imutável, `detach`/shutdown
determinísticos) reusa o mesmo motor de scan que as tools síncronas, sem
duplicá-lo.

**`resume_token` não está implementado nesta versão.** A seção "Retomada
correta" desta spec descreve um cursor autoritativo com fingerprint de
região, CAS de admissão e estado de overlap serializado por operação — um
subsistema à parte, do tamanho de uma spec própria. Implementá-lo apressado
arriscava perder ou duplicar matches na fronteira, exatamente o defeito que a
spec existe para evitar. `scan_start` aceita a forma `resume_token` no
schema e responde de forma segura e explícita
(`unsupported`/`resume_not_supported`) em vez de simular suporte; nenhum
token é emitido em `job_status`/`job_results` (`resume_token` sempre `null`).
`next_start_address` é preenchido de forma best-effort para `scan_exact` e
`scan_pointers_to` quando o job é truncado por `byte_budget`/`result_limit` —
permanece diagnóstico, nunca aceito como cursor. Esta lacuna é o ponto de
extensão prioritário para um passe futuro; ver o relatório de implementação
para os detalhes de design que ele deve preservar (motor compartilhado,
progresso via callback aditivo, guarda de exclusão mútua bypassável apenas
pelo próprio worker).

## Escopo

A primeira versão deve aceitar como jobs as operações longas que usam o motor
de scan existente:

- `scan_exact`;
- `strings`;
- `scan_pointers_to`;
- `scan_pointer_chains`;
- `scan_first`;
- `scan_next`.

Cada operação mantém seu contrato tipado. `scan_start` não encaminha um
objeto JSON arbitrário ao domínio: o protocol layer valida a variante escolhida
e a converte para um request C++ específico.

Não fazem parte desta proposta:

- persistência de jobs ou resultados após o encerramento do servidor;
- escrita no processo-alvo;
- execução de código no processo-alvo;
- notificações push de progresso como requisito de funcionamento;
- paralelismo ilimitado de scans sobre uma mesma sessão.

## Invariantes

1. Todo job pertence exatamente a uma `SessionId` de depuração e nunca pode ser
   consultado por outra sessão.
2. Um job não sobrevive a `detach`, ao shutdown do servidor nem ao processo MCP.
3. Resultados só são publicados como snapshot imutável; paginação nunca observa
   um vetor sendo modificado pelo worker.
4. Nenhum mutex permanece retido durante leitura do alvo, espera de worker,
   serialização extensa ou outra operação de I/O.
5. Cancelamento é cooperativo e verificado entre chunks e entre regiões.
6. Fila, workers, trabalho total, resultados retidos e tempo de retenção possuem
   limites rígidos definidos no servidor.
7. `next_start_address` é diagnóstico. Somente `resume_token` pode retomar um
   scan sem lacunas ou duplicações de fronteira.
8. `stdout` continua reservado exclusivamente ao protocolo MCP/JSON-RPC.

## Estados e ciclo de vida

```text
queued ───────► running ───────► completed
  │                │             │
  │                ├────────────► cancelled
  │                └────────────► failed
  └─────────────────────────────► cancelled
```

Os estados têm a seguinte semântica:

| Estado | Semântica |
|---|---|
| `queued` | Aceito e retido numa fila limitada; nenhum byte do alvo foi lido. |
| `running` | Um worker possui a execução do job. |
| `completed` | A execução terminou normalmente, inclusive quando um limite explícito causou truncagem. |
| `cancelled` | Um pedido cooperativo de parada venceu a corrida com a conclusão. |
| `failed` | A execução terminou por erro seguro, como alvo encerrado ou falha interna. |

`cancel_requested` é um atributo transitório, não um sétimo estado. Um job pode
permanecer `running` por um curto período depois de `job_cancel`, até o
worker alcançar o próximo checkpoint. Estados terminais não voltam a estados
ativos.

`job_release` remove um job terminal, inclusive com resultados expirados,
imediatamente. Remoção
não é um estado observável: depois dela, chamadas pelo mesmo identificador
retornam `not_found`. Um job `queued` ou `running` deve primeiro ser cancelado;
`release` nesses estados retorna `invalid_state`.

Quando termina o TTL de resultados, o registro mantém seu estado terminal
imutável, libera itens, scan sessions ainda não transferidas e `resume_token`,
e passa a informar `results_expired: true`. Um tombstone limitado conserva
estado, progresso final e motivo; um segundo TTL remove o registro.

## Motivo de término e cobertura

Todo estado terminal possui `stop_reason` explícito:

| `stop_reason` | Estado esperado | Truncado | Retomável |
|---|---|---:|---:|
| `operation_completed` | `completed` | não | não |
| `range_exhausted` | `completed` | somente se um limite de resultado foi atingido sem parar o sweep | não |
| `byte_budget` | `completed` | sim | sim |
| `result_limit` | `completed` | sim | sim |
| `deadline` | `completed` | sim | sim |
| `max_depth` | `completed` | sim | quando a operação define checkpoint BFS |
| `max_fanout` | `completed` | sim | quando a operação define checkpoint BFS |
| `client_cancelled` | `cancelled` | não | quando existe checkpoint seguro |
| `session_detached` | `cancelled` | não | não |
| `server_shutdown` | `cancelled` | não | não |
| `target_exited` | `failed` | não | não |
| `read_error` | `failed` | não | não |
| `stale_snapshot` | `failed` | não | não |
| `unstable_snapshot` | `failed` | não | não |
| `internal_error` | `failed` | não | não |

`coverage_complete` só é `true` quando toda região elegível foi processada e
não houve lacuna de leitura. `results_complete` só é `true` quando todo match
do escopo elegível foi contabilizado e retido conforme o contrato; portanto
também é falso se a cobertura for incompleta. O campo compatível `complete` é
derivado como `coverage_complete && results_complete`. `truncated` só é `true`
quando um limite normal impede cobertura ou resultados completos, mesmo que um
sweep multipadrão continue em count-only. Cancelamento e falha deixam os dois
campos de completude falsos, mas não são disfarçados como truncagem.

`stop_reason` é a causa primária do fim do worker. A lista fechada
`truncation_reasons` registra todos os limites observados (`byte_budget`,
`result_limit`, `deadline`, `max_depth`, `max_fanout` e limites por item
aplicáveis). Isso permite `stop_reason: "range_exhausted"` com
`truncation_reasons: ["result_limit"]` quando um matcher entrou em count-only
mas o sweep continuou para os demais. Gaps de leitura são expostos por
`read_error_count` e por uma lista bounded de intervalos/erros seguros; não são
silenciosamente convertidos em ausência de match.

`truncation_reasons` também inclui `retained_bytes_budget` quando
`AnalysisJobManager` não consegue reter todos os matches encontrados dentro de
`ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES` — um orçamento agregado somado
sobre os resultados retidos de todos os jobs, não por job. Diferente dos
demais motivos, esse corte acontece depois que o sweep já terminou: um job
pode chegar com `coverage_complete: true` (o scan cobriu tudo) e ainda assim
`results_complete: false` porque o excedente de resultados foi descartado
para caber no orçamento agregado. `job_release`, a expiração do TTL de
resultados e `detach_session` devolvem os bytes ao orçamento.

Falhas não fatais de leitura continuam registradas em `regions_skipped` e
`bytes_skipped`. Assim, um job pode chegar a `range_exhausted` com
`complete: false`; essa diferença deve permanecer visível em vez de promover
cobertura parcial a sucesso completo.

## Contrato de domínio

Tipos propostos em `argos_domain`, sem JSON, MCP, logging ou handles nativos:

```cpp
class AnalysisJobId final { /* identificador opaco validado */ };
class ScanResumeToken final { /* identificador opaco validado */ };

enum class AnalysisJobKind {
    scan,
    pointer_index,
    unreal_runtime
};

enum class AnalysisJobState {
    queued,
    running,
    completed,
    cancelled,
    failed
};

enum class AnalysisStopReason {
    operation_completed,
    range_exhausted,
    byte_budget,
    result_limit,
    deadline,
    max_depth,
    max_fanout,
    client_cancelled,
    session_detached,
    server_shutdown,
    target_exited,
    read_error,
    stale_snapshot,
    unstable_snapshot,
    internal_error
};

enum class AnalysisTruncationReason {
    byte_budget,
    result_limit,
    deadline,
    max_depth,
    max_fanout,
    retained_bytes_budget  // ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES, aggregate across all retained jobs.
};

struct ScanProgress {
    std::uint64_t sequence{};
    std::size_t bytes_scanned{};
    std::size_t bytes_eligible{};
    std::size_t bytes_skipped{};
    std::size_t regions_scanned{};
    std::size_t regions_eligible{};
    std::size_t regions_skipped{};
    std::size_t matches_found{};
    std::size_t matches_retained{};
};

struct AnalysisJobTermination {
    AnalysisStopReason reason{};
    bool coverage_complete{false};
    bool results_complete{false};
    bool truncated{false};
    std::vector<AnalysisTruncationReason> truncation_reasons;
    std::size_t read_error_count{};
    std::optional<Address> next_start_address;
    std::optional<ScanResumeToken> resume_token;
};

using AnalysisJobProgress = std::variant<
    ScanProgress,
    PointerIndexProgress,
    UnrealRuntimeProgress>;

using AnalysisJobResult = std::variant<
    ScanJobResult,
    PointerIndexJobResult,
    UnrealRuntimeJobResult>;

struct AnalysisJobInfo {
    AnalysisJobId id;
    SessionId owner;
    AnalysisJobKind kind{};
    AnalysisJobState state{};
    bool cancel_requested{false};
    bool results_available{false};
    bool results_expired{false};
    AnalysisJobProgress progress;
    std::optional<AnalysisJobTermination> termination;
};

using AsyncScanRequest = std::variant<
    ExactScanRequest,
    StringScanRequest,
    PointerScanRequest,
    PointerChainScanRequest,
    FirstScanRequest,
    NextScanRequest>;
```

`AnalysisStopReason` é a união fechada do wire contract. No domínio, o reason
é discriminado por `AnalysisJobKind` + operação (variant ou request tipado):
scan não produz `unstable_snapshot`, pointer-index build não produz
`max_fanout`, e Unreal não inventa reason de outra operação. O serializer é
exaustivo e testes rejeitam combinações impossíveis.

`ScanProgress::sequence` cresce a cada snapshot publicado. Os contadores
nunca diminuem dentro do mesmo job. `coverage_ratio` é calculado na camada de
apresentação a partir de `bytes_scanned` e `bytes_eligible`, evitando armazenar
um float suscetível a inconsistência.

`AnalysisJobInfo` é o envelope comum reutilizável. Specs 0010 e 0012 definem as
variantes tipadas de progresso/resultado de `pointer_index` e
`unreal_runtime`; nenhuma delas usa mapa JSON genérico no domínio nem cria um
segundo manager/pool. Novas capacidades acrescentam uma variante fechada sem
mudar as quatro tools de controle.

`scan_first` mantém candidatos num draft transacional pertencente à cadeia de
continuação. O padrão da primeira versão não publica sessão parcial: um único
`scan_id` só é criado quando o job termina com `range_exhausted`,
`coverage_complete: true` e `results_complete: true`. Budget, deadline,
cancelamento ou result cap podem produzir resultados diagnósticos e um token,
mas não um `scan_id`; expirar/liberar esse token destrói o draft. Isso cumpre a
promessa de uma única scan session cobrindo o alvo sem permitir que ela pareça
global quando contém só uma janela.

`scan_next` mantém a geração original intacta durante todos os jobs de uma
continuação e só faz o replace COW/CAS quando as mesmas três condições de
completude forem verdadeiras. Cada job ativo obtém uma lease RAII; entre jobs,
o token guarda `scan_id` + geração esperada. Se `scan_next`, `scan_reset`,
`scan_close` ou detach mudar essa geração/lifetime antes da retomada, o token
falha como stale. Cancelamento, falha ou continuação incompleta descartam o
draft e não avançam a geração original.

A primeira versão não oferece `allow_partial_session`. Se essa opção for
adicionada no futuro, a sessão deverá carregar coverage parcial permanente e
jamais promover um resultado vazio a conclusão negativa.

## Ownership, RAII e concorrência

`AnalysisJobManager`, na camada de aplicação, possui:

- registry limitado de `AnalysisJobId → shared_ptr<JobRecord>`;
- fila limitada de jobs ainda não iniciados;
- conjunto fixo de workers `std::jthread`;
- um `std::stop_source` por job;
- snapshots imutáveis de resultado, publicados por troca/move ao terminalizar.

O `shared_ptr` é justificado porque registry, worker e uma chamada curta de
`status`/`results` podem observar o mesmo record fora do lock. O payload grande
é construído privadamente pelo worker. O lock protege apenas estado pequeno,
transições e publicação do snapshot; leitura do processo e join nunca ocorrem
sob esse lock.

Uma transição terminal é linearizada uma única vez. Se conclusão e cancelamento
correrem, a primeira transição aceita vence: ou o job fica `completed`, ou fica
`cancelled`; jamais publica dois resultados nem troca de terminal depois.

O servidor pode continuar processando uma chamada MCP foreground por vez. Os
workers de scan são uma fila de aplicação separada; por isso `status`, `cancel`
e `results` continuam disponíveis enquanto um job roda em background, sem
exigir paralelismo irrestrito de handlers MCP. Scans síncronos e jobs
assíncronos compartilham o mesmo limite de execução por sessão; o padrão
proposto é no máximo um scan longo `running` por sessão.

### `detach`

`memory_debug_detach` segue esta ordem:

1. marca a sessão como `closing` e impede novos jobs;
2. remove jobs `queued` da fila e terminaliza-os como `cancelled` com
   `session_detached`;
3. pede stop aos jobs `running`;
4. aguarda, fora dos locks do registry, que os workers liberem a referência à
   sessão;
5. destrói resultados, tokens e scan sessions pertencentes à sessão;
6. libera o handle nativo por RAII e retorna.

O motor verifica stop entre chunks de tamanho limitado, o que torna a espera de
`detach` limitada pelo trabalho de um chunk e pela latência da chamada nativa
em andamento. Não há thread destacada que possa continuar usando o handle.

### Shutdown

No shutdown, o manager fecha a aceitação, cancela toda a fila com
`server_shutdown`, pede stop aos jobs ativos, acorda os workers e faz join de
todos os `std::jthread` antes de destruir sessions/providers. Nenhuma resposta
tardia é escrita em `stdout` após o encerramento do transporte.

## Retomada correta

`next_start_address` representa o primeiro endereço lógico ainda não atribuído
ao job encerrado. Ele serve para diagnóstico humano e cálculo de cobertura,
mas não contém informação suficiente para continuar um scanner.

`resume_token` é o cursor autoritativo. Ele referencia estado mantido pelo
servidor e fica vinculado a:

- instância do servidor;
- `session_id` proprietário;
- operação e hash dos argumentos validados;
- snapshot/fingerprint das regiões elegíveis;
- região e cursor lógico atuais;
- alinhamento do tipo ou padrão;
- estado de fronteira específico da operação.

O token não é um endereço serializado, não é aceito em outra sessão e deixa de
existir em `release`, expiração, `detach` ou shutdown. Se o mapa de regiões não
corresponder ao fingerprint esperado, a continuação falha com
`stale_resume_token` em vez de pular ou repetir silenciosamente uma faixa.

Tokens são single-use e consumidos por CAS quando um novo job é admitido. Isso
impede duas ramificações de publicarem o mesmo draft. Se o job seguinte parar
num checkpoint seguro, ele emite outro token; se a admissão falhar antes do
CAS, o token original continua válido. Draft, counters cumulativos, carry e
geração esperada ficam em snapshot COW bounded, contabilizado na quota/TTL.

### Overlap de chunks e padrões

Para um padrão de `W` bytes, cada chunk posterior relê ou preserva até `W - 1`
bytes do chunk anterior. Um match cuja primeira posição seja anterior ao cursor
lógico do chunk já processado não é emitido novamente. A mesma regra vale ao
retomar por token: o scanner recompõe o overlap, mas só publica matches cujo
início pertença à nova faixa lógica.

Overlap entre duas regiões só é permitido quando elas são contíguas e ambas
pertencem ao mesmo conjunto elegível; uma lacuna ou mudança incompatível de
proteção encerra a fronteira. Toda soma `address + size` verifica overflow.
Scans tipados usam a largura do tipo e preservam a fase de alinhamento. Scans de
string carregam no token um estado parcial limitado pelo máximo configurado de
resultado, nunca um buffer sem limite.

Esse estado adicional explica por que recomeçar apenas de
`next_start_address` poderia perder um valor dividido entre chunks ou duplicar
um match já emitido.

## Contrato de API (MCP)

As cinco tools propostas usam polling e, portanto, funcionam nas três versões
de protocolo preservadas pela ADR-0016. A criação é específica de scan; as
quatro tools de controle são genéricas para poderem servir também a futuros
jobs de indexação e introspecção:

- `memory_debug_scan_start`;
- `memory_debug_job_status`;
- `memory_debug_job_results`;
- `memory_debug_job_cancel`;
- `memory_debug_job_release`.

Todas exigem `session_id`; as quatro últimas também exigem `job_id`. Um par
`session_id`/`job_id` que não pertença ao mesmo owner retorna `not_found`, sem
revelar que o job existe em outra sessão.

### Start de um job novo

```json
{
  "name": "memory_debug_scan_start",
  "arguments": {
    "session_id": "session_…",
    "operation": "scan_exact",
    "request": {
      "pattern": "d4087105",
      "writable_only": true,
      "result_limit": 4096
    },
    "execution": {
      "byte_budget": 4294967296,
      "deadline_ms": 300000
    }
  }
}
```

`operation` seleciona uma variante fechada no input schema; `request` é
validado pelo mesmo parser da tool síncrona correspondente. Os limites pedidos
em `execution` só podem reduzir ou selecionar valores dentro da policy do
servidor. O job continua atravessando chunks internos até esgotar a faixa ou
atingir um desses limites — o orçamento não é reiniciado a cada chunk.

Resposta imediata:

```json
{
  "ok": true,
  "data": {
    "job_id": "job_…",
    "job_kind": "scan",
    "operation": "scan_exact",
    "state": "queued",
    "cancel_requested": false
  }
}
```

Se a requisição MCP que executa `scan_start` for cancelada antes da
resposta, qualquer job já inserido recebe stop e não fica órfão. Depois que o
start retorna, cancelar uma requisição MCP qualquer não cancela o job; o
cliente usa `job_cancel`.

### Status e progresso

```json
{
  "name": "memory_debug_job_status",
  "arguments": {"session_id": "session_…", "job_id": "job_…"}
}
```

```json
{
  "ok": true,
  "data": {
    "job_id": "job_…",
    "job_kind": "scan",
    "operation": "scan_exact",
    "state": "running",
    "cancel_requested": false,
    "progress": {
      "sequence": 37,
      "bytes_scanned": 805306368,
      "bytes_eligible": 3484033024,
      "bytes_skipped": 0,
      "regions_scanned": 4210,
      "regions_eligible": 18292,
      "regions_skipped": 0,
      "matches_found": 18,
      "matches_retained": 18,
      "coverage_ratio": 0.2311,
      "elapsed_ms": 12480
    },
    "termination": null,
    "results_available": false
  }
}
```

Um status terminal truncado torna o motivo inequívoco:

```json
{
  "ok": true,
  "data": {
    "job_id": "job_…",
    "job_kind": "scan",
    "operation": "scan_exact",
    "state": "completed",
    "cancel_requested": false,
    "progress": {
      "sequence": 104,
      "bytes_scanned": 2147483648,
      "bytes_eligible": 3484033024,
      "bytes_skipped": 0,
      "regions_scanned": 11021,
      "regions_eligible": 18292,
      "regions_skipped": 0,
      "matches_found": 4096,
      "matches_retained": 4096,
      "coverage_ratio": 0.6164,
      "elapsed_ms": 40792
    },
    "termination": {
      "stop_reason": "result_limit",
      "coverage_complete": false,
      "results_complete": false,
      "complete": false,
      "truncated": true,
      "truncation_reasons": ["result_limit"],
      "read_error_count": 0,
      "next_start_address": "0x1FE49001234",
      "resume_token": "resume_…"
    },
    "results_available": true,
    "expires_in_ms": 300000
  }
}
```

Depois do TTL, `progress`, estado e motivo terminal podem permanecer no
tombstone, mas `results_available` é `false`, `results_expired` é `true`,
`resume_token` não é devolvido e `job_results` retorna `expired`.

### Resultados

```json
{
  "name": "memory_debug_job_results",
  "arguments": {
    "session_id": "session_…",
    "job_id": "job_…",
    "offset": 0,
    "limit": 100
  }
}
```

```json
{
  "ok": true,
  "data": {
    "job_id": "job_…",
    "job_kind": "scan",
    "operation": "scan_exact",
    "items": [
      {"address": "0x1FE44726C90"}
    ],
    "page": {
      "offset": 0,
      "returned": 1,
      "total": 4096,
      "has_more": true
    },
    "termination": {
      "stop_reason": "result_limit",
      "coverage_complete": false,
      "results_complete": false,
      "complete": false,
      "truncated": true,
      "truncation_reasons": ["result_limit"],
      "read_error_count": 0
    }
  }
}
```

O payload de `items` é discriminado por `operation` e conserva os campos da
tool síncrona correspondente. `scan_first`/`scan_next` só devolvem `scan_id`,
`generation` e `candidate_count` quando o snapshot completo foi transferido
para `ScanSessionManager`; em qualquer resultado parcial, esses campos são
`null`/ausentes e `draft_retained_for_resume` informa se o token ainda possui o
draft. Paginação (`page.has_more`) é separada da truncagem da execução
(`termination.truncated`).

Resultados ficam disponíveis apenas depois de um estado terminal. Um job
cancelado pode expor um snapshot parcial de matches quando alcançou um
checkpoint seguro, sempre marcado `complete: false`; em `scan_first` e
`scan_next`, esse snapshot não cria nem altera a scan session. Um job `failed`
não publica um vetor parcialmente construído como se fosse resultado válido.

### Cancelamento

```json
{
  "name": "memory_debug_job_cancel",
  "arguments": {"session_id": "session_…", "job_id": "job_…"}
}
```

```json
{
  "ok": true,
  "data": {
    "job_id": "job_…",
    "job_kind": "scan",
    "state": "running",
    "cancel_requested": true
  }
}
```

Cancelar `queued` o remove da fila e terminaliza imediatamente. Cancelar
`running` apenas pede stop; o cliente consulta `status` até `cancelled`. Se o
job já for terminal, a chamada é idempotente e informa o estado vencedor sem
reescrevê-lo.

### Liberação

```json
{
  "name": "memory_debug_job_release",
  "arguments": {"session_id": "session_…", "job_id": "job_…"}
}
```

```json
{"ok": true, "data": {"job_id": "job_…", "job_kind": "scan", "released": true}}
```

O fluxo recomendado é `cancel` → aguardar estado terminal → `release`. A
liberação remove resultados, continuação e tombstone. Ela não afeta uma scan
session já transferida por `scan_first`/`scan_next`; essa sessão continua com o
ciclo de vida da ADR-0009.

### Continuação

O schema de `scan_start` usa `oneOf`: ou recebe `operation` + `request`, ou
recebe somente um `resume_token` além de `session_id` e limites de execução.

```json
{
  "name": "memory_debug_scan_start",
  "arguments": {
    "session_id": "session_…",
    "resume_token": "resume_…",
    "execution": {"deadline_ms": 300000}
  }
}
```

Argumentos de operação conflitantes são rejeitados. O cliente não pode passar
`next_start_address` como cursor. Um token é single-use e consumido
atomicamente na admissão. Enquanto o job/tombstone existir, repetir a mesma
requisição com o token consumido devolve o mesmo `job_id`; argumentos
divergentes falham. Isso torna retry de transporte idempotente sem ramificar o
draft. Todos os jobs continuam sujeitos aos limites de backpressure.

## Erros de API

As propostas reutilizam `DebugErrorCode`; não criam um código novo para cada
estado interno. Quando útil, a resposta adiciona um `reason` fechado e seguro:

- `invalid_argument`: operação/paginação/fresh-resume inválido; reasons como
  `ambiguous` ficam nesta classe;
- `not_found`: sessão/job inexistente, owner divergente ou job já liberado;
- `invalid_state`: results/release em job ativo, lease concorrente ou token
  inutilizável; reasons `results_expired` e `stale_resume_token`;
- `limit_exceeded`: fila cheia, jobs, bytes, deadline ou retenção acima da
  policy; reason `job_queue_full` substitui um código novo `server_busy`;
- `unsupported`: job kind/profile/formato não suportado, com reason específico;
- `parse_error`: artefato persistido corrompido;
- `io_error`: falha nativa traduzida, sem texto cru;
- `cancelled`: cancelamento de uma chamada MCP curta, distinto do estado do
  job em background.

Mensagens nativas permanecem traduzidas para erros seguros.

## Compatibilidade com tools síncronas e eras MCP

As tools atuais mantêm nomes, schemas, limites, cancelamento request-scoped e
semântica. Elas não passam a criar jobs retidos implicitamente. O motor tipado
de scan e as regras de overlap devem ser compartilhados pelos caminhos
síncrono e assíncrono para evitar divergência de resultados.

Um scan síncrono conta contra o mesmo slot de execução longa da sessão. Se um
job já estiver `running`, outra operação longa na mesma sessão recebe
`invalid_state` com reason `analysis_job_active` ou entra na fila apenas quando
chamada pela API assíncrona. Tools curtas de controle de job não entram nessa
fila.

O polling não depende de uma extensão de progresso do protocolo. Em MCP
`2026-07-28`, respostas usam somente `structuredContent` conforme ADR-0016; nos
protocolos legados, preservam também o `TextContent` compatível. A notificação
JSON-RPC/MCP de cancelamento continua linearizada com a requisição que carrega
seu ID; ela não substitui `job_cancel` para trabalho já destacado da
requisição `start`.

O `_meta.resultType: "complete"` da ADR-0016 descreve a conclusão daquela
chamada curta de `start/status/results/cancel/release`; não significa que o job
em background esteja `completed`, nem substitui os campos de cobertura e
resultado desta spec.

## Backpressure e limites

`SecurityPolicy` deve controlar, com hard caps independentes de qualquer valor
pedido pelo cliente:

- jobs totais e jobs por sessão, incluindo terminais retidos;
- tamanho da fila global e por sessão;
- workers globais e jobs simultâneos por sessão;
- bytes máximos e deadline máxima por job;
- itens e bytes máximos de resultado por job;
- bytes totais de resultados retidos pelo servidor;
- TTL de resultados e TTL do tombstone expirado;
- tamanho máximo de padrão e de estado de overlap.

A fila é limitada e FIFO, com cota por sessão para impedir que um único owner a
preencha. Nenhuma chamada pode elevar os hard caps. Falha de admissão ocorre
antes de alocar buffers grandes ou iniciar leitura do alvo. Resultados
terminais contam contra a cota até `release` ou expiração.

Um job com cobertura completa processou a faixa autorizada sem lacunas; um job
com resultados completos também reteve todos os matches exigidos pelo
contrato. Nenhum dos dois significa “sem policy”. Se um limite impedir uma das
garantias, a resposta termina com motivo explícito e, quando seguro,
continuação.

## Segurança

A capacidade permanece somente leitura e reutiliza `authorize_scan`; um job
não amplia a autorização concedida no `attach`. Identificadores e tokens são
opacos, têm entropia suficiente e são vinculados ao owner. O servidor nunca
aceita path, handle ou ponteiro nativo fornecido como estado de continuação.

Os riscos novos são consumo prolongado de CPU/I/O, retenção de dados derivados
da memória e aumento de concorrência. As mitigações são fila e pool limitados,
deadline, byte budget, limite de resultados, TTL, cancelamento cooperativo,
quota por sessão e destruição determinística em `detach`/shutdown. O desenho
deve ser incorporado à seção de negação de serviço do
[threat model](../threat-model/runtime-memory-debug.md) antes de ser
implementado.

Resultados e endereços possuem a mesma sensibilidade das tools síncronas. O
TTL não transforma o servidor em armazenamento persistente; nenhum job ou
token é gravado em disco.

## Observabilidade

Transições produzem logs estruturados em `stderr` com `job_id`, operação,
estado anterior/novo, profundidade da fila, duração, contagens agregadas e
`stop_reason`. Não registrar:

- padrão ou valor pesquisado;
- endereços encontrados ou `next_start_address`;
- bytes da memória;
- `resume_token`;
- conteúdo dos resultados;
- mensagens nativas completas.

Progresso exposto ao cliente contém apenas contagens e duração. Logs de
cancelamento, expiração e shutdown permitem detectar jobs abandonados sem
vazar o alvo. `stdout` recebe exclusivamente frames MCP/JSON-RPC.

## Plano de testes

### Unidade

- fixture com latch/barrier, nunca `sleep`, prova que start retorna antes do I/O
  e que status/cancel continuam atendendo enquanto o reader está bloqueado;
- todas as transições válidas e rejeição de transições depois de terminal;
- corrida conclusão × cancelamento com exatamente um vencedor;
- cancelamento em `queued` sem executar o body, em `running`, depois de terminal
  e duas vezes de forma idempotente;
- cancelamento em cada fronteira de chunk e liberação da lease de scan session;
- progresso monotônico e snapshot coerente sob leituras concorrentes;
- expiração libera payload grande e conserva apenas tombstone limitado;
- `release` com reader concorrente não causa UAF: o snapshot imutável vive até
  a última referência;
- fila, workers, quota por sessão, bytes, resultados, deadline e TTL nos
  limites mínimo/máximo;
- `detach` e shutdown cancelam, aguardam workers e liberam handles por RAII;
- overflow em cursor, overlap, endereço final e contadores é rejeitado.

### Scan e continuação

- padrão dividido exatamente entre dois chunks é encontrado uma vez;
- padrão no overlap não é duplicado;
- budget exatamente igual ao último byte elegível termina
  `range_exhausted`/não truncado; um byte menor termina `byte_budget` com cursor
  correto;
- `result_limit` atingido antes do fim e exatamente no último hit não sofre
  off-by-one;
- continuação por token reproduz o resultado de uma passagem monolítica;
- `next_start_address` sozinho não é aceito como cursor;
- padrão de um byte, padrão do tamanho máximo e chunk menor que o padrão;
- regiões contíguas elegíveis e regiões separadas por lacuna;
- gaps/short reads incrementam coverage errors e nunca viram ausência
  conclusiva;
- cursor/overlap perto de `UINT64_MAX` falha checked, sem wrap;
- alinhamento de todos os tipos de `scan_first`/`scan_next` após retomada;
- token de outra sessão, expirado, liberado, com argumentos divergentes e com
  fingerprint de regiões obsoleto;
- retry idêntico de token consumido devolve o mesmo job; tentativa de branch
  não cria segundo draft;
- `scan_first` interrompido não publica `scan_id` e a cadeia completa publica
  exatamente um; `scan_next` interrompido mantém a geração original até o CAS
  terminal;
- cancelamento só devolve token quando o checkpoint é consistente.

### Contrato MCP

- as cinco tools aparecem em `tools/list` apenas quando a implementação for
  entregue, com `inputSchema` e `outputSchema` completos;
- campos ausentes, tipos errados, estado incompatível, owner divergente e
  paginação extrema;
- exemplos fresh e resume passam pelo parser e pelo serializer;
- `page.has_more` não é confundido com `termination.truncated`;
- sequência start → status → results → release nas três versões MCP da
  ADR-0016;
- cancelamento da requisição `start` não deixa job órfão;
- cancelamento de `status`/`results` não altera o job em background;
- tools síncronas mantêm respostas e testes de regressão existentes.

### Integração e toolchain

- alvo controlado maior que o orçamento síncrono: job cobre toda a faixa e
  coincide com um resultado de referência;
- backpressure sob múltiplas sessões sem starvation permanente;
- alvo encerrado durante leitura termina como `failed/target_exited`;
- `detach` durante leitura e shutdown com fila cheia não deixam thread ou
  handle vivo;
- ASan/UBSan e TSan em builds separadas, além de warnings elevados em MSVC,
  Clang e GCC quando suportados.

Benchmarks devem registrar tamanho do alvo, chunks, workers, throughput,
latência de cancelamento, memória máxima de resultados e custo de polling. O
número de workers não deve ser aumentado sem evidência de ganho e sem revisar o
impacto no processo-alvo.

## Critérios de aceite

- um alvo maior que o orçamento síncrono pode ser varrido até
  `range_exhausted` sem cálculo manual de janelas;
- progresso é monotônico, limitado e consultável enquanto o job roda;
- todos os estados e motivos de término são observáveis e não ambíguos;
- cobertura e completude dos resultados são independentes e nunca inferidas de
  `state: completed`;
- cancelamento, `detach` e shutdown não deixam worker, handle, lease, resultado
  ou token órfão;
- fila, concorrência, trabalho e retenção são limitados e testados;
- resultado paginado é imutável e compatível com a tool síncrona equivalente;
- um padrão que cruza chunk ou continuação não é perdido nem duplicado;
- somente `resume_token`, nunca `next_start_address`, retoma uma operação;
- scan sessions só são publicadas após cobertura e resultados completos;
- as tools síncronas e as três eras MCP permanecem compatíveis;
- nenhuma capacidade de escrita, injeção, evasão ou elevação é adicionada;
- threat model, API e README são atualizados quando — e somente quando — a
  implementação correspondente for entregue.

## Referências internas

- [Roadmap — Eficiência do agente em alvo real](0007-roadmap-eficiencia-agente.md)
- [ADR-0002 — Sessões explícitas e autorização](../adr/0002-explicit-debug-sessions.md)
- [ADR-0009 — Sessões de scan incremental](../adr/0009-value-diff-scan-sessions.md)
- [ADR-0012 — Scans assíncronos, progresso e retomada](../adr/0012-async-scan-progress-resumption.md)
- [ADR-0016 — Compatibilidade MCP dual-era](../adr/0016-mcp-dual-era-2026.md)
- [Threat model — depuração de memória em runtime](../threat-model/runtime-memory-debug.md)

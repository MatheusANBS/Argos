# ADR-0012 — Scans assíncronos, progresso e retomada

Status: aceito (retomada por `resume_token` permanece como extensão futura —
ver a "Nota de implementação" na [Spec 0008](../specs/0008-async-scan-operations.md))

## Contexto

As tools de scan atuais são síncronas, limitadas por chamada e executadas no
worker associado à requisição MCP. Em um alvo real com gigabytes elegíveis,
isso obriga o cliente a dividir o espaço em janelas, acompanhar vários
resultados e inferir por que cada passagem terminou. O caso medido no
[roadmap 0007](../specs/0007-roadmap-eficiencia-agente.md) exigiu dezenas de
chamadas para uma busca que deveria ser uma única operação acompanhável.

Elevar apenas o teto de bytes não resolve o problema: aumenta risco de negação
de serviço, mantém uma requisição aberta por muito tempo e não oferece
progresso, retenção ou cancelamento explícito do trabalho depois que a chamada
original termina. Retornar apenas o próximo endereço também é insuficiente,
porque scanners precisam preservar alinhamento, região atual e overlap de
padrão para não perder ou duplicar matches na fronteira.

O desenho precisa preservar:

- autorização e lifetime da sessão definidos na
  [ADR-0002](0002-explicit-debug-sessions.md);
- ownership das scan sessions definido na
  [ADR-0009](0009-value-diff-scan-sessions.md);
- compatibilidade dos envelopes e cancelamento request-scoped da
  [ADR-0016](0016-mcp-dual-era-2026.md);
- limites contra leitura excessiva descritos no
  [threat model](../threat-model/runtime-memory-debug.md).

O contrato detalhado está na
[Spec 0008](../specs/0008-async-scan-operations.md). `AnalysisJobManager` e as
cinco tools estão implementados; a retomada por `resume_token` descrita nesta
decisão é a exceção documentada — ver a "Nota de implementação" da spec.

## Decisão

### Jobs de aplicação com polling

Introduzir `AnalysisJobManager` na camada de aplicação e cinco tools aditivas.
A criação é específica do tipo de análise; status, resultados, cancelamento e
liberação são genéricos para que pointer index e introspecção possam reutilizar
o mesmo lifecycle:

- `memory_debug.scan_start`;
- `memory_debug.job_status`;
- `memory_debug.job_results`;
- `memory_debug.job_cancel`;
- `memory_debug.job_release`.

Polling é o contrato obrigatório porque funciona nas três eras MCP suportadas.
Notificações de progresso podem ser avaliadas futuramente como otimização, mas
não serão necessárias para correção nem para lifecycle.

`scan_start` recebe uma variante fechada e validada das operações longas de
scan e registra `job_kind: "scan"`.
JSON existe somente no protocol layer; o domínio recebe tipos C++ específicos.
Os caminhos síncrono e assíncrono reutilizam o mesmo motor de scan e a mesma
política de autorização.

### Máquina de estados

Todo job pertence a uma sessão de depuração e transita somente por:

```text
queued → running → completed
   │         ├──→ cancelled
   │         └──→ failed
   └────────────→ cancelled
```

`completed` significa que o worker encerrou normalmente; a cobertura ainda
pode estar truncada por um limite. `cancelled` significa que um pedido de stop
venceu a corrida com a conclusão. `failed` contém apenas erro externo seguro.
Estados terminais são imutáveis. Quando o TTL termina, resultado e continuação
são destruídos, mas um tombstone preserva estado terminal, motivo e
`results_expired: true` por um período curto. `release` remove um registro
terminal; expiração e release não reescrevem a máquina de estados.

Conclusão e cancelamento têm um único ponto de linearização. O primeiro estado
terminal publicado vence. `cancel_requested` é apenas um indicador enquanto o
worker ainda não alcançou um checkpoint.

### Progresso e término explícito

`status` expõe snapshots monotônicos e limitados: sequência, bytes e regiões
elegíveis/processados/pulados, matches encontrados/retidos, cobertura e duração.
Não expõe bytes da memória.

Todo job terminal informa `stop_reason`. Os motivos normais incluem
`operation_completed`, `range_exhausted`, `byte_budget`, `result_limit` e `deadline`; cancelamentos
distinguem cliente, `detach` e shutdown; falhas distinguem alvo encerrado,
erro de leitura e erro interno. `coverage_complete`, `results_complete` e
`truncated` são campos separados. O `complete` legado é derivado da conjunção
dos dois primeiros; cancelamento ou falha não são apresentados como truncagem
normal. `truncation_reasons` é uma lista fechada, pois um job multipadrão pode
esgotar o limite de um item e ainda varrer o restante até `range_exhausted`.
Gaps de leitura ficam numa contagem/lista limitada própria, sem serem
confundidos com “nenhum match”.

### Continuação

Quando existe checkpoint retomável, a resposta inclui:

- `next_start_address`, apenas informativo;
- `resume_token`, opaco e autoritativo.

O token é vinculado à instância do servidor, sessão proprietária, operação,
argumentos, fingerprint das regiões, cursor, alinhamento e estado de fronteira.
Ele não sobrevive a `release`, expiração, `detach` ou shutdown.

O token é consumido por CAS e referencia um draft COW bounded. Retry idêntico
enquanto o tombstone existir devolve o mesmo `job_id`; uma segunda ramificação
não é criada. `scan_first` só publica `scan_id` e `scan_next` só faz commit de
geração quando `range_exhausted`, cobertura completa e resultados completos
forem verdadeiros. Sessões parciais não são publicadas na primeira versão.

Para um padrão de `W` bytes, o scanner preserva ou relê até `W - 1` bytes de
overlap e só emite matches cujo início pertença à nova faixa lógica. O mesmo
critério vale entre chunks internos e ao retomar. Um endereço sozinho não
substitui esse estado; por isso a API nunca aceita `next_start_address` como
cursor de continuação.

### Ownership, RAII e shutdown

O manager possui uma fila limitada e um conjunto fixo de `std::jthread`; não
há uma thread destacada por job. Cada job possui `std::stop_source`. Registry,
worker e leitores curtos podem compartilhar um `JobRecord` por `shared_ptr`,
enquanto resultado grande é construído privadamente e publicado como snapshot
imutável.

Locks protegem apenas registry, fila, transições e publicação. Nenhum mutex é
mantido durante I/O do alvo, serialização, espera ou join.

`detach` marca a sessão como fechando, rejeita novos jobs, cancela os jobs
`queued`/`running`, espera os workers liberarem a sessão fora dos locks,
destrói resultados/tokens/scan sessions pertencentes ao owner e então libera o
handle nativo por RAII. Shutdown fecha a fila, pede stop global, faz join de
todos os workers e só depois destrói sessions/providers.

Uma operação assíncrona de `scan_next` mantém lease exclusiva e RAII sobre sua
scan session até terminalizar. Isso evita duas gerações concorrentes e garante
liberação em todos os caminhos de erro ou cancelamento. Somente um job
`completed` publica a nova geração; cancelamento ou falha descartam o draft e
preservam a scan session anterior.

### Backpressure

`SecurityPolicy` define hard caps para:

- jobs e fila, globalmente e por sessão;
- workers e scans simultâneos por sessão;
- bytes e deadline por job;
- quantidade e bytes de resultados;
- memória total retida;
- TTL do resultado e do tombstone;
- padrão e overlap máximos.

A admissão falha antes de buffers grandes ou leitura do alvo. O padrão é um
scan longo ativo por sessão; jobs excedentes entram apenas na fila limitada.
Resultados terminais continuam consumindo quota até `release` ou expiração.

### Compatibilidade

As tools síncronas existentes não mudam nome, schema ou lifetime e não criam
jobs ocultos. Elas compartilham o motor e contam contra o mesmo slot de scan
longo da sessão.

Os workers rodam em background, mas o dispatcher pode continuar serializando
uma chamada MCP foreground por vez; as tools curtas de controle permanecem
disponíveis enquanto o job executa. Isso não implica paralelismo irrestrito de
`tools/call`.

Em `2026-07-28`, as respostas seguem `structuredContent`; clientes legados
mantêm a representação textual definida na ADR-0016. Cancelamento MCP da
requisição `start` não deixa job órfão. Depois da resposta de `start`, somente
`job_cancel` altera o lifecycle do job; cancelar uma chamada de `status`
ou `results` não o cancela.

### Segurança e observabilidade

A mudança permanece read-only e reutiliza `authorize_scan`. IDs e tokens são
opacos, têm owner e não são persistidos. Quotas, deadline, TTL e cancelamento
cooperativo mitigam CPU, I/O e retenção prolongados. O threat model deve ser
atualizado antes da implementação.

Logs estruturados vão exclusivamente para `stderr` e podem conter job,
operação, transição, profundidade da fila, duração, contagens e motivo de
término. Não registram padrões, valores, endereços, bytes, resultados ou
`resume_token`. `stdout` permanece exclusivo do protocolo.

## Consequências

- um cliente pode solicitar cobertura integral dentro da policy e acompanhar a
  operação com poucas chamadas pequenas;
- cancelamento deixa de depender da permanência da requisição inicial;
- motivo de término, cobertura e retomada deixam de ser inferidos pelo cliente;
- overlap e alinhamento ficam sob responsabilidade de um cursor autoritativo,
  reduzindo risco de falso negativo ou duplicação em fronteiras;
- tools e clientes existentes continuam válidos;
- surge estado concorrente e retido no servidor, exigindo fila limitada,
  quotas, TTL, testes de corrida e shutdown determinístico;
- resultados podem ocupar memória por mais tempo que numa chamada síncrona, até
  `release` ou expiração;
- `detach` pode aguardar o término cooperativo do chunk nativo em andamento;
- jobs não sobrevivem ao processo MCP e não são um mecanismo de persistência.

## Alternativas rejeitadas

### Apenas elevar `ARGOS_MCP_MAX_SCAN_BYTES`

Mantém chamadas longas, não oferece progresso nem lifecycle explícito e amplia
o risco de DoS sem backpressure por job.

### Usar somente notificações de progresso MCP

Não resolve retenção, paginação, reconnect dentro da mesma instância nem
compatibilidade uniforme com clientes legados.

### Retomar por `next_start_address`

Perde alinhamento e overlap do padrão e não representa estado específico de
strings, tipos ou pointer chains.

### Uma thread destacada por job

Não fornece limite natural, ownership ou join confiável em `detach`/shutdown e
abre caminho para UAF do handle de processo.

## Verificação exigida para aceitação futura

- testes de contrato das cinco tools nas três eras MCP;
- máquina de estados, cancelamento concorrente, expiração e release;
- padrão cruzando chunk e continuação encontrado exatamente uma vez;
- fila cheia, quotas globais/por sessão e retenção máxima;
- `detach` e shutdown com jobs `queued` e `running`, sem thread/handle órfão;
- regressão integral das tools síncronas;
- ASan/UBSan e TSan em builds separadas, warnings elevados e benchmark de
  throughput, memória e latência de cancelamento;
- revisão do [threat model](../threat-model/runtime-memory-debug.md), da API e
  do README quando a implementação for entregue.

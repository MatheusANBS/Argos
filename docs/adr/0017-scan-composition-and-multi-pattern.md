# ADR-0017 — Composição de candidatos e scan multipadrão

Status: proposto

## Contexto

ADR-0009 introduziu sessões incrementais, mas cada `scan_first` ainda cria um
conjunto fechado de candidatos a partir de uma única varredura e de um único
tipo. Endereços encontrados por `scan_exact`, por outra janela, por uma análise
externa autorizada ou por uma execução anterior do cliente não podem ser
alimentados em `scan_next`. Da mesma forma, procurar o mesmo valor como `i32`,
`u32`, `i64`, `f32` e como assinatura de bytes exige reler o processo para cada
representação, embora o custo dominante seja a leitura da memória.

O teste real descrito em
[`docs/specs/0007-roadmap-eficiencia-agente.md`](../specs/0007-roadmap-eficiencia-agente.md)
precisou manter candidatos no cliente e executar várias passagens. Uma API de
composição deve reduzir esse I/O sem permitir que o cliente injete snapshots
inconsistentes ou contorne os limites de sessão.

## Decisão

Serão adicionadas duas capacidades somente-leitura:

1. `memory_debug.scan_import` cria uma `ScanSession` a partir de endereços
   explícitos. O servidor ordena e deduplica os endereços, valida overflow de
   `address + value_size` e lê o valor inicial diretamente do processo. O
   cliente não fornece o baseline. A sessão resultante usa o mesmo ownership,
   geração, batching, COW, limites e teardown de ADR-0009 e pode ser consumida
   imediatamente por `scan_next`.
2. `memory_debug.scan_start` com `operation: "multi_pattern"` compila uma lista
   limitada de valores tipados e padrões exatos e os compara durante uma única
   leitura de cada chunk elegível. Cada entrada possui `pattern_id` estável e
   único. O resultado é materializado pelo modelo de jobs da Spec 0008, com
   paginação por `{pattern_id, address}` e contagens por padrão.

`scan_import` oferece política explícita para erro de leitura:

- `reject_all` é o padrão transacional: qualquer endereço inválido impede a
  criação da sessão;
- `skip_unreadable` cria a sessão somente com leituras bem-sucedidas e retorna
  contagem e erros seguros dos itens rejeitados, limitados pelo contrato.

O motor multipadrão recebe padrões já codificados no domínio, sem JSON. A
implementação inicial agrupa candidatos por primeiro byte, largura e
alinhamento; o algoritmo concreto permanece encapsulado para poder ser
substituído por um autômato quando benchmarks justificarem. A decisão
invariante é fazer **uma passagem de I/O**, preservar `max_pattern_size - 1`
bytes entre chunks contíguos e nunca perder ou duplicar matches em retomadas.

Valores tipados aceitam a mesma codificação decimal segura de `scan_first`.
`value_type: "auto"` é açúcar de protocolo que expande uma entrada em padrões
tipados com IDs derivados e sem nova leitura. Padrões de bytes são exatos nesta
fase; máscaras e wildcards ficam fora de escopo.

Uma entrada comum não pode esgotar a memória destinada às demais. Há limite
global e por padrão. Quando o limite de armazenamento de um padrão é atingido,
o job continua a varredura em modo de contagem para os demais e marca o padrão
individual como truncado. A criação opcional de `ScanSession` só é permitida
para entradas de valor tipado e continua limitada por
`max_scan_session_candidates` e `max_scan_sessions_per_session`.
Ela é transacional: só publica todas as sessões-filhas se cobertura e
resultados de todos os padrões tipados forem completos. Não publica sessão
parcial nem um subconjunto silencioso na primeira versão.

Como uma importação ou materialização consome quota até `detach`, será
adicionada também `memory_debug.scan_close`. Ela remove uma scan session do
owner somente quando não existe lease de `scan_next`; não substitui
`scan_reset`, que conserva a identidade e apenas esvazia candidatos.

Não será adicionada dependência externa. O matcher pertence ao domínio; leitura
do alvo continua na infraestrutura e apresentação JSON continua em Protocol/MCP.

## Consequências

- candidatos de janelas, tools e clientes diferentes passam a convergir em um
  único `scan_next`;
- múltiplas representações deixam de multiplicar `ReadProcessMemory`/
  `process_vm_readv`;
- ordenação e deduplicação preservam o batching contíguo já implementado em
  `scan_next`;
- o custo de CPU cresce com o número e o tamanho dos padrões, exigindo limites
  próprios e benchmark antes de alterar o matcher;
- o servidor retém mais resultados derivados, mas nunca bytes arbitrários do
  processo além do baseline tipado já previsto por ADR-0009;
- `scan_exact` e `scan_first` permanecem compatíveis; clientes não são forçados
  a migrar;
- nenhuma escrita, injeção, mudança de proteção ou execução no processo-alvo é
  introduzida.

## Verificação

A Spec 0009 define contratos, limites, testes de fronteira de chunk, fairness,
rollback transacional, cancelamento, teardown e a meta de uma única passagem
nativa por região elegível.

# Spec 0009 — Composição de scans e busca multipadrão

Status: proposto · ADR: [0017](../adr/0017-scan-composition-and-multi-pattern.md)

## Objetivo

Permitir que endereços descobertos por qualquer fonte autorizada entrem no
pipeline `scan_next` e procurar vários valores/padrões em uma única passagem de
memória. A proposta estende ADR-0009 e depende do modelo assíncrono da
[Spec 0008](0008-async-scan-operations.md); não altera as tools já implementadas.

## Estado atual e lacuna

- `ScanSessionManager::create` só é chamado por `scan_first`;
- `scan_next` é eficiente depois da primeira geração, mas não aceita uma lista
  externa de candidatos;
- `scan_exact` e `scan_first` trabalham com um padrão/tipo por passagem;
- o cliente precisa repetir a leitura do mesmo espaço para testar outras
  representações;
- candidatos já são armazenados em ordem e `scan_next` agrupa endereços
  contíguos, portanto importação sem normalização quebraria uma otimização
  existente.

## Contratos de domínio

```cpp
enum class ImportReadPolicy { reject_all, skip_unreadable };

struct ScanImportResult {
    ScanSessionInfo info;
    std::size_t supplied{};
    std::size_t accepted{};
    std::size_t duplicates{};
    std::size_t rejected{};
    std::vector<BatchItemError> errors; // limitada pela policy
};

struct MultiPattern {
    std::string id;
    std::vector<std::byte> bytes;
    std::size_t alignment{1};
    std::optional<ScanValueType> value_type;
};

struct MultiPatternMatch {
    std::uint32_t pattern_index{};
    Address address{};
};
```

Casos de uso de aplicação:

```cpp
Result<ScanImportResult> scan_import(
    const SessionId& owner,
    ScanValueType value_type,
    std::span<const Address> addresses,
    ImportReadPolicy read_policy,
    std::stop_token cancellation = {}
);

Result<AnalysisJobInfo> start_multi_pattern_scan(
    const SessionId& owner,
    std::span<const MultiPattern> patterns,
    const ScanRange& range,
    const ScanFilters& filters,
    const MultiPatternLimits& limits
);
```

Esta spec acrescenta `MultiPatternScanRequest` à variante fechada
`AsyncScanRequest` da Spec 0008; não cria um dispatcher JSON paralelo.

O domínio não recebe JSON, handles nativos ou paths. O serviço lê o baseline
de candidatos importados fora do mutex do registry. A publicação da sessão é
atômica: em `reject_all`, nenhuma sessão existe se qualquer leitura falhar.

Antes da publicação, endereços são ordenados e deduplicados. Endereço zero é
permitido apenas se a plataforma realmente o expuser como região legível;
`address + scan_value_size(type)` deve ser representável sem overflow. Não há
exigência implícita de alinhamento para importação: campos válidos podem ser
packed. A leitura do baseline agrupa intervalos dentro de
`max_read_bytes`; nenhum batch nativo ou buffer cresce com a lista inteira.

Endereços são interpretados exclusivamente na `ProcessIdentity` da sessão viva
e a resposta inclui seu fingerprint público. Importar uma lista salva pelo
cliente não a torna portável: restart do alvo, PID reuse ou outra sessão exige
nova descoberta/revalidação, ainda que um endereço antigo por acaso seja
legível. O baseline sempre é o valor atual lido pelo servidor.

## API MCP — `memory_debug_scan_import`

```json
{
  "session_id": "…",
  "value_type": "u32",
  "addresses": ["0x1FE44726C90", "0x1FE781A2CD0"],
  "on_read_error": "reject_all"
}
```

Resposta:

```json
{
  "ok": true,
  "data": {
    "scan_id": "…",
    "value_type": "u32",
    "candidate_count": 2,
    "generation": 0,
    "supplied": 2,
    "accepted": 2,
    "duplicates": 0,
    "rejected": 0
  }
}
```

Depois disso, o contrato atual funciona sem variante especial:

```json
{"scan_id":"…","comparison":"exact","value_decimal":"91293808"}
```

Em `skip_unreadable`, `errors` segue o modelo seguro por item de `read_batch` e
é truncado por um limite próprio. A resposta sempre diferencia `supplied`,
`accepted`, `duplicates`, `rejected` e `candidate_count`.

### `memory_debug_scan_close`

```json
{"session_id":"…","scan_id":"…"}
```

```json
{"ok":true,"data":{"scan_id":"…","closed":true}}
```

A tool exige o owner e libera candidatos/baseline imediatamente. Se um
`scan_next` possui lease ativa, retorna `invalid_state`; depois do terminal o
cliente pode tentar novamente. `detach` continua fechando todas as sessões do
owner. Fechar duas vezes é idempotente para o mesmo owner durante um tombstone
curto, sem revelar IDs pertencentes a outra sessão.

## API MCP — `memory_debug_scan_start` / `multi_pattern`

```json
{
  "name": "memory_debug_scan_start",
  "arguments": {
    "session_id": "…",
    "operation": "multi_pattern",
    "request": {
      "patterns": [
        {
          "pattern_id": "credits:i32",
          "kind": "value",
          "value_type": "i32",
          "value_decimal": "91293908",
          "alignment": 4
        },
        {
          "pattern_id": "credits:u64",
          "kind": "value",
          "value_type": "u64",
          "value_decimal": "91293908",
          "alignment": 8
        },
        {
          "pattern_id": "credits-save-tag",
          "kind": "bytes",
          "pattern_hex": "4372656469747300",
          "alignment": 1
        }
      ],
      "writable_only": true,
      "materialize_scan_sessions": true
    },
    "execution": {
      "byte_budget": 4294967296,
      "deadline_ms": 300000,
      "result_limit": 16384
    }
  }
}
```

Resposta imediata:

```json
{
  "ok": true,
  "data": {
    "job_id": "…",
    "job_kind": "scan",
    "operation": "multi_pattern",
    "state": "queued"
  }
}
```

`memory_debug_job_results` pagina:

```json
{
  "name": "memory_debug_job_results",
  "arguments": {
    "session_id": "…",
    "job_id": "…",
    "offset": 0,
    "limit": 100
  }
}
```

```json
{
  "ok": true,
  "data": {
    "job_id": "…",
    "job_kind": "scan",
    "operation": "multi_pattern",
    "items": [
      {"pattern_id":"credits:i32","address":"0x1FE44726C90"}
    ],
    "patterns": [
      {
        "pattern_id":"credits:i32",
        "match_count":42,
        "stored_count":42,
        "truncated_by_result_limit":false,
        "scan_id":"…"
      }
    ],
    "page": {"offset":0,"returned":1,"total":42,"has_more":false},
    "termination": {
      "stop_reason":"range_exhausted",
      "coverage_complete":true,
      "results_complete":true,
      "complete":true,
      "truncated":false,
      "truncation_reasons":[]
    }
  }
}
```

`pattern_id` é único, UTF-8 válido, limitado em tamanho e retornado sem
alteração. `materialize_scan_sessions` ignora entradas `kind: "bytes"`; a
resposta identifica explicitamente quais padrões produziram `scan_id`.

Sessões tipadas só são materializadas quando o job alcança `range_exhausted`,
a cobertura global é completa e **todos os padrões tipados** têm resultados
completos. Se qualquer um atingir limite por item/global, todos os `scan_id`
ficam `null` e `materialization_reason: "incomplete_results"`; a primeira
versão não cria sessão parcial nem oferece override. As sessões-filhas são
publicadas num único commit: falha/cancelamento não deixa um subconjunto
visível.

### `value_type: "auto"`

Uma entrada `kind: "value"`, `value_type: "auto"` e `value_decimal` expande,
por padrão, para `i32`, `u32`, `i64`, `u64`, `f32` e `f64` quando o literal cabe
no tipo. IDs são derivados como `<pattern_id>:<type>`. Tipos incompatíveis são
listados em `skipped_encodings`; não causam truncamento silencioso. Para floats,
a codificação determinística usa round-to-nearest/ties-to-even e a resposta
também informa o decimal efetivamente representado e os bytes codificados,
tornando arredondamento IEEE-754 visível ao cliente. O conjunto completo de
IDs explícitos e derivados é validado antes de I/O; qualquer colisão, inclusive
entre `<id>` e `<outro-id>:<type>`, rejeita a requisição inteira.

## Semântica de uma passagem

- regiões são enumeradas uma vez e lidas em chunks reutilizáveis;
- cada byte do alvo é lido no máximo uma vez por job, exceto fallback explícito
  de short-read;
- o carry é `max_pattern_size - 1` somente dentro de intervalos contíguos;
- matches na sobreposição de chunk ou de `resume_token` são deduplicados por
  `{pattern_index, address}`;
- alinhamento é calculado sobre o endereço virtual, não sobre o índice local do
  buffer;
- um padrão que atinge seu limite passa a `count_only`; os demais continuam
  armazenando resultados;
- falha de leitura de uma região aparece em cobertura/terminação e nunca é
  convertida em “nenhum match”.

## Limites e segurança

Policies propostas:

| Limite | Padrão sugerido | Teto rígido |
|---|---:|---:|
| padrões por job | 32 | 256 |
| bytes somados dos padrões | 4 KiB | 64 KiB |
| tamanho de um padrão | 1 KiB | 16 KiB |
| resultados armazenados por padrão | 4.096 | policy global de resultados do job |
| endereços por `scan_import` | 65.536 | 262.144 e frame MCP de 8 MiB |
| erros por item retornados | 64 | 1.024 |

Entradas são validadas antes de iniciar I/O: IDs duplicados, padrão vazio,
hex inválido, alinhamento que não seja potência de dois, literal fora da faixa
e soma de bytes acima do limite retornam `invalid_argument` ou
`limit_exceeded`.

As duas tools exigem uma sessão autorizada existente e não criam nova classe
de acesso. Nenhum valor, padrão, endereço ou byte lido entra em logs. `stderr`
recebe apenas `job_id`/`scan_id`, contagens, duração e motivo de término.

## Estruturas de dados e performance

- candidatos importados: `std::vector<ScanCandidate>` ordenado, com
  deduplicação linear após `sort`;
- padrões compilados: armazenamento contíguo e buckets pelo primeiro byte,
  largura e alinhamento;
- resultados: índices numéricos de padrão, convertidos para IDs apenas na
  apresentação MCP;
- baseline obrigatório: tempo, bytes/s, leituras nativas, alocações e memória
  retida para 1, 8, 32 e 256 padrões;
- critério principal: o número de leituras nativas não cresce com a quantidade
  de padrões para o mesmo mapa de regiões.

Uma mudança para autômato ou SIMD exige benchmark e não altera o contrato.

## Plano de testes

### Unitários

- importação fora de ordem e com duplicatas publica vetor ordenado/deduplicado;
- `reject_all` faz rollback quando um item falha;
- `skip_unreadable` publica somente sucessos e limita erros retornados;
- overflow de endereço, sessão inexistente, tipo inválido e limite de
  candidatos;
- lista reaproveitada após mudança de process identity não ganha proveniência
  de sessão anterior e é reamostrada/rejeitada na sessão atual;
- `scan_next` sobre sessão importada cobre `exact`, `changed`, `decreased_by`
  e batching contíguo;
- dois padrões com prefixo comum e matches sobrepostos;
- padrão cruzando dois chunks contíguos é encontrado uma vez;
- padrão não cruza um buraco entre regiões;
- alinhamentos diferentes usam o endereço virtual correto;
- um padrão muito comum não impede resultados de outro;
- padrão truncado nunca produz `scan_id`; materialização de várias sessões é
  all-or-nothing quanto à publicação;
- `value_type:auto` codifica somente tipos representáveis;
- arredondamento float é determinístico e colisões entre IDs derivados são
  rejeitadas antes de I/O;
- cancelamento não publica sessão parcial sem indicação explícita;
- `scan_close` concorrente com `scan_next` não causa UAF, respeita lease e
  libera a quota depois do terminal.

### Contrato

- schemas impõem `oneOf` entre `value_decimal`/`value`/`pattern_hex`;
- IDs duplicados, campos conflitantes e listas vazias são rejeitados;
- jobs expõem progresso/resultados conforme Spec 0008;
- ferramentas atuais permanecem byte-a-byte compatíveis.

### Performance

- provider instrumentado confirma uma enumeração de regiões e uma leitura de
  cada chunk para 1 e N padrões;
- benchmark registra throughput e alocações sem promover otimização não medida.

## Critérios de aceite

- candidatos arbitrários passam por ao menos dois `scan_next` sem recriar o
  scan original;
- `reject_all` é transacional e `detach` remove toda sessão importada;
- `scan_close` permite liberar deterministicamente uma sessão importada;
- 32 padrões não multiplicam as leituras do processo;
- nenhum match é perdido ou duplicado em fronteira de chunk/retomada;
- limites globais e por padrão são visíveis separadamente;
- logs e `stdout` preservam as regras de segurança e protocolo.

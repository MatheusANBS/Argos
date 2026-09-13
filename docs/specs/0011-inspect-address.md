# Spec 0011 — Inspeção bounded de endereço

Status: implementado · ADR: [0013](../adr/0013-address-inspection-derived-evidence.md)

## Estado da entrega

`memory_debug_inspect_address` está implementada: classificador puro no domínio
(`domain/address_inspection.hpp`), orquestração em `MemoryDebugService` e
contrato MCP em `protocol/mcp/tools.cpp`. Região, módulo/RVA, candidatos
rankeados com `probable`/confidence/evidence/provenance, limites, limitações
tipadas e referências `live_scan` com cobertura e `resume_token` seguem o
contrato abaixo.

Duas diferenças em relação ao texto original, por dependência não implementada:

- `references.mode: "index"` é validado e recusado com `unsupported`. Ele
  depende da [Spec 0010](0010-persistent-pointer-index.md); um downgrade
  silencioso para `live_scan` mudaria custo e cobertura sem o cliente saber.
  `next_cursor` já existe na resposta, sempre `null`, para que a forma não mude
  quando o índice chegar;
- `live_scan` é um slice síncrono e bounded. Ele já expõe cobertura,
  `resume_token` autoritativo, `next_start_address` apenas diagnóstico e
  `truncation_reasons`; o modelo de job/cancelamento assíncrono da ADR-0012
  permanece proposto.

O plano de testes está em `tests/unit/test_address_inspection.cpp`
(`SparseFakeSession` em `tests/unit/sparse_fake_session.hpp`) e nas asserções de
contrato em `tests/contract/test_mcp_contract.cpp`.

## Objetivo

Adicionar `memory_debug_inspect_address` para correlacionar, em uma resposta
pequena e somente-leitura, um endereço com região, proteções, módulo/RVA,
candidatos prováveis de objeto/vtable e referências opcionais. A tool reduz a
classificação manual de candidatos sem transformar heurística em fato.

Esta proposta compõe:

- a [ADR-0011](../adr/0011-reverse-pointer-chain-scan.md), para scans reversos
  e cadeias limitadas;
- a [ADR-0012](../adr/0012-async-scan-progress-resumption.md), proposta, para
  cobertura, cursor, retomada, cancelamento e motivos de término;
- a [ADR-0018](../adr/0018-persistent-pointer-index.md), proposta, e a
  [Spec 0010](0010-persistent-pointer-index.md), proposta, para referências por
  índice persistente.

## Estado atual e lacuna

O MCP já oferece `regions`, `modules`, `read`, `read_batch`,
`scan_pointers_to` e `scan_pointer_chains`. Para responder “este endereço pode
ser um campo dentro de qual objeto?”, o cliente ainda precisa:

1. baixar mapas separados;
2. calcular módulo/RVA;
3. ler manualmente bytes anteriores;
4. interpretar dwords/qwords como ponteiros;
5. verificar à mão se uma suposta vtable leva a código executável;
6. iniciar outro scan para referências.

Esse fluxo transfere bytes crus, repete lookups, dificulta distinguir ausência
de evidência de scan incompleto e tende a apresentar um único palpite mesmo
quando vários inícios de objeto são plausíveis.

## Invariantes

- a capacidade é exclusivamente read-only;
- toda classificação de objeto/vtable é `probable`, inclusive com confiança
  alta;
- `field_offset` é derivado entre dois endereços, não um offset de propriedade
  confirmado;
- `null` e arrays vazios representam ausência; nenhum dado é inventado;
- intervalos são semiabertos e aritmética de endereço é checked;
- `pointer_size` descreve o alvo e é obrigatoriamente `4` ou `8`;
- nenhum scan de referências ocorre sem pedido e orçamento explícitos;
- toda lista e texto da resposta têm limite;
- domínio não conhece MCP, JSON, SO, logging, filesystem nem handles.

## Contratos de domínio

Os nomes abaixo são indicativos; o contrato semântico é normativo.

```cpp
enum class TargetPointerWidth : std::uint8_t { x86 = 4, x64 = 8 };
enum class DerivedConfidence { low, medium, high };
enum class ReferenceSource { none, index, live_scan };

enum class EvidenceKind {
    object_base_in_readable_region,
    object_base_in_writable_region,
    vtable_in_readable_region,
    vtable_in_non_writable_region,
    vtable_owned_by_module,
    executable_vtable_entry,
    non_executable_vtable_entry,
    short_vtable_sample,
    same_module_code_targets
};

enum class ProvenanceKind {
    region_map_snapshot,
    module_map_snapshot,
    bounded_memory_sample,
    derived_vtable_shape,
    pointer_index_snapshot,
    live_reverse_scan
};

struct RegionDescriptor {
    Address start{};
    Address end{};
    bool readable{};
    bool writable{};
    bool executable{};
    bool private_mapping{};
    std::string name;
};

struct ModuleRelativeAddress {
    std::string module_name;
    Address module_base{};
    std::uint64_t rva{};
};

struct DerivedEvidence {
    EvidenceKind kind{};
    std::uint32_t observed{};
    std::uint32_t sampled{};
};

struct ProbableObjectCandidate {
    Address object_address{};
    std::uint64_t field_offset{};
    Address vtable_address{};
    std::optional<ModuleRelativeAddress> vtable_module;
    DerivedConfidence confidence{};
    std::vector<DerivedEvidence> evidence;
    std::vector<ProvenanceKind> provenance;
};
```

O classificador puro recebe:

- endereço inspecionado;
- largura do ponteiro;
- bytes efetivamente amostrados e seu endereço-base;
- probes bounded das possíveis vtables;
- mapas de região/módulo já normalizados e ordenados;
- limites/réguas de confiança.

Ele devolve candidatos e limitações sem executar I/O. Endereços de módulo são
representados por índice interno durante o ranking; strings só são materializadas
na borda da resposta.

Application é responsável por obter um único snapshot de regiões e módulos,
validá-lo, efetuar leituras fora de mutexes de registry e passar observações ao
domínio. Infrastructure continua responsável apenas pelas leituras nativas.

## API MCP — `memory_debug_inspect_address`

### Requisição

```json
{
  "session_id": "…",
  "address": "0x1FE44726C90",
  "pointer_size": "8",
  "lookbehind_bytes": 2048,
  "max_object_candidates": 8,
  "vtable_entries": 8,
  "min_executable_entries": 3,
  "references": {
    "mode": "index",
    "index_id": "…",
    "result_limit": 64,
    "cursor": null
  }
}
```

Campos:

| Campo | Regra |
|---|---|
| `session_id` | obrigatório; sessão autorizada existente |
| `address` | string hexadecimal, `uint64_t` |
| `pointer_size` | obrigatório: `"4"` ou `"8"`; nunca herdado do host |
| `lookbehind_bytes` | janela máxima anterior ao endereço; bounded pela policy |
| `max_object_candidates` | limite de candidatos devolvidos, não permissão para probes ilimitados |
| `vtable_entries` | `K` entradas máximas amostradas por vtable |
| `min_executable_entries` | mínimo observado para a forma entrar no ranking |
| `references` | ausente equivale a `mode: "none"` |

`lookbehind_bytes`, `vtable_entries`, `min_executable_entries` e limites de
candidatos devem satisfazer relações validadas antes de qualquer leitura. Em
particular, `min_executable_entries <= vtable_entries`.

### Referências por índice

```json
{
  "mode": "index",
  "index_id": "…",
  "result_limit": 64,
  "cursor": "…"
}
```

- `index_id` pertence à mesma sessão e pointer width;
- `result_limit` é o orçamento explícito de materialização da consulta;
- o resultado herda `bytes_indexed`, `bytes_eligible`, regiões, orçamento,
  timestamp, fingerprint e truncamentos do build descrito na Spec 0010;
- índice parcial, stale, cancelado ou construído sobre outro snapshot é
  identificado e nunca tratado como cobertura completa;
- cursor opaco é autenticado/vinculado a índice, alvo, filtros e posição.

### Referências por scan ao vivo

```json
{
  "mode": "live_scan",
  "byte_budget": 33554432,
  "result_limit": 64,
  "writable_only": false,
  "start_address": "0x10000",
  "end_address": "0x7FFFFFFFFFFF",
  "resume_token": null
}
```

- `byte_budget` e `result_limit` são obrigatórios;
- o slice reutiliza o motor reverso e o modelo de cobertura/retomada da
  ADR-0012; não inicia uma varredura sem limite;
- cancelamento usa `std::stop_token` e não publica uma resposta tardia para o
  request cancelado;
- retomada usa `resume_token` opaco e autoritativo, não um endereço cru que
  perderia carry/estado; `next_start_address` é somente diagnóstico;
- resultado vazio só é conclusivo com `complete: true`.

`index_id` é proibido em `live_scan`; `byte_budget` é proibido em `index`. A
validação usa `oneOf`, não precedência silenciosa.

As duas fontes expõem orçamento sem unidade ambígua:

- `index` devolve o `byte_budget`/deadline usados no build, mais o
  `result_limit` da consulta corrente;
- `live_scan` devolve o `byte_budget`, deadline quando houver e
  `result_limit` pedidos para o slice corrente.

Em `index`, `next_cursor` pagina o `equal_range` já materializado. Em
`live_scan`, `resume_token` retoma o motor conforme ADR-0012 e
`next_start_address` nunca é aceito como continuação.

### Resposta

```json
{
  "ok": true,
  "data": {
    "address": "0x1FE44726C90",
    "pointer_size": "8",
    "sampled_at_ms": 1786320000123,
    "region": {
      "start": "0x1FE44726000",
      "end": "0x1FE44728000",
      "readable": true,
      "writable": true,
      "executable": false,
      "private": true,
      "name": ""
    },
    "module": null,
    "analysis": {
      "lookbehind_bytes_requested": 2048,
      "lookbehind_bytes_read": 2048,
      "vtable_probes_attempted": 3,
      "vtable_probes_complete": 3,
      "complete": true,
      "limitations": []
    },
    "object_candidates": [
      {
        "rank": 0,
        "classification": "probable",
        "object_address": "0x1FE44726700",
        "field_offset": 1424,
        "vtable": {
          "address": "0x7FF7F5A01230",
          "module": "FSD-Win64-Shipping.exe",
          "module_base": "0x7FF7F4000000",
          "rva": 27267632
        },
        "confidence": "high",
        "evidence": [
          {"kind":"vtable_owned_by_module","observed":1,"sampled":1},
          {"kind":"executable_vtable_entry","observed":7,"sampled":8}
        ],
        "provenance": [
          "region_map_snapshot",
          "module_map_snapshot",
          "bounded_memory_sample",
          "derived_vtable_shape"
        ]
      }
    ],
    "object_candidates_total": 1,
    "object_candidates_truncated": false,
    "references": {
      "mode": "index",
      "budget": {
        "byte_budget": 3484033024,
        "result_limit": 64,
        "source": "index_build"
      },
      "matches": [],
      "coverage": {
        "bytes_scanned": 3484033024,
        "bytes_eligible": 3484033024,
        "regions_scanned": 18292,
        "regions_eligible": 18292,
        "coverage_ratio": 1.0,
        "complete": true
      },
      "next_cursor": null,
      "resume_token": null,
      "next_start_address": null,
      "truncation_reasons": []
    }
  }
}
```

`module` no topo descreve o dono do endereço inspecionado. `vtable.module`
descreve separadamente o dono da vtable provável. RVAs são números sem sinal e
só aparecem junto de um módulo confirmado por faixa.

Toda resposta diferencia:

- nenhum mapping: `region: null`;
- nenhum módulo: `module: null`;
- nenhuma forma de objeto com evidência mínima: `object_candidates: []`;
- análise parcial: `analysis.complete: false` com `limitations`;
- nenhuma referência em cobertura total: array vazio e `complete: true`;
- nenhuma referência encontrada ainda: array vazio e `complete: false`, estado
  de continuação e/ou motivo explícito.

Não são usados sentinelas como endereço zero, RVA `-1`, módulo `"unknown"` ou
vtable vazia fabricada.

## Algoritmo de lookbehind e ranking

1. Enumerar regiões e módulos uma vez, ordenar e validar intervalos.
2. Encontrar a região contendo `address` por busca binária.
3. Se não houver região legível, devolver correlação disponível com candidatos
   vazios; não tentar leitura especulativa.
4. Calcular `window_start = max(region.start, address - lookbehind_bytes)` e
   `window_end = min(region.end, checked_add(address, pointer_size))`; ler essa
   faixa uma vez e considerar somente ponteiros completos. O limite de
   lookbehind mede distância, enquanto o buffer total pode incluir até um
   ponteiro no endereço inspecionado.
5. Enumerar bases alinhadas a `pointer_size` dentro da amostra completa.
6. Decodificar dword/qword little-endian sem cast desalinhado.
7. Manter somente vptrs que caiam em região legível, não gravável e pertencente
   a módulo; limitar probes antes de qualquer leitura adicional.
8. Ler em batch até `K * pointer_size` bytes por possível vtable, com overflow
   e short read explícitos.
9. Para cada entrada completa, verificar por busca no mapa se aponta para região
   executável; nunca dereferenciar a função.
10. Classificar e ordenar deterministicamente; materializar somente os melhores
    `max_object_candidates`.

O score é interno e versionado. A resposta expõe fatos suficientes para auditar
o ranking, não somente um número opaco. Regras mínimas:

- uma forma sem `min_executable_entries` não vira candidato;
- vtable em região não gravável de módulo é requisito da primeira versão;
- entradas executáveis no mesmo módulo aumentam confiança;
- short read reduz completude/confiança e nunca é preenchido com zeros;
- confiança alta exige mais de um sinal independente, mas continua probable;
- empates usam, nesta ordem, evidência executável, menor `field_offset` e menor
  endereço.

## x86 e x64

- x86 lê exatamente 4 bytes por ponteiro e valida aritmética no espaço de
  endereço representável pelo alvo;
- x64 lê exatamente 8 bytes;
- ambos decodificam little-endian byte a byte ou por helper seguro;
- nenhum caminho depende da bitness do processo MCP;
- WOW64 não autoriza truncar um endereço de 64 bits: argumento incompatível é
  rejeitado;
- alinhamento é calculado pelo endereço virtual, não pelo offset do buffer.

## Resposta bounded e policies

Valores iniciais sugeridos, sujeitos a benchmark e revisão de segurança:

| Limite | Padrão | Teto rígido |
|---|---:|---:|
| `lookbehind_bytes` | 512 B | 16 KiB |
| bases examinadas | derivado da janela | 4.096 |
| probes de vtable | 16 | 128 |
| `vtable_entries` (`K`) | 8 | 64 |
| candidatos devolvidos | 8 | 64 |
| evidências por candidato | 16 | 32 |
| proveniências por candidato | 8 | 16 |
| referências por página | 64 | policy global de resultados |
| limitações retornadas | 16 | 64 |

Nomes de região/módulo continuam sujeitos a limites de string do protocolo.
`object_candidates_total` conta somente formas que atingiram evidência mínima;
`object_candidates_truncated` informa se nem todas foram materializadas.

## Segurança

- requer sessão explicitamente autorizada conforme ADR-0002;
- lê somente regiões marcadas como legíveis;
- não escreve, muda proteção, injeta DLL/código, cria remote thread, chama
  funções do alvo, eleva privilégio, oculta atividade ou contorna proteção;
- valida `address + size`, subtração do lookbehind, módulo+RVA e
  `vtable + K * pointer_size` antes de I/O;
- limites são aplicados antes de alocar ou ler;
- índice, cursor e `resume_token` são opacos, pertencem à sessão e carregam
  versão/fingerprint;
- erros não incluem mensagem nativa, bytes nem paths internos;
- referências e nomes podem revelar layout sensível do processo autorizado e
  não são persistidos além dos contratos explícitos de Spec 0010;
- nenhuma entrada externa é usada para montar shell command.

## Observabilidade

Eventos estruturados permitidos em `stderr`:

- início/fim com correlation ID opaco;
- duração total e por fase;
- bytes solicitados/lidos;
- quantidade de regiões/módulos, bases, probes e candidatos;
- `pointer_size`, modo de referências, cobertura e motivos de término;
- cancelamento e erro tipado seguro.

Nunca registrar:

- endereço alvo, object/vtable/function pointers ou referências;
- bytes de memória;
- nomes/paths de módulo/região;
- `session_id`, `index_id`, cursor, `resume_token` ou argumentos completos;
- mensagens nativas completas.

`stdout` contém exclusivamente frames JSON-RPC/MCP.

## Performance e estruturas de dados

- regiões e módulos: `std::vector` normalizado/ordenado, consultado por busca
  binária;
- lookbehind: um buffer contíguo reutilizável e uma leitura bounded;
- probes de vtable: `read_batch`/coalescing quando faixas forem adjacentes;
- candidatos: vetor limitado, com seleção parcial dos top N quando benchmark
  justificar;
- refs `index`: lookup do índice, sem novo scan do alvo;
- refs `live_scan`: uma passagem por slice, chunks reutilizados e orçamento da
  requisição;
- nenhum mapa é re-enumerado por candidato;
- memória auxiliar é `O(regions + modules + lookbehind + probes*K + resposta)`.

Baseline obrigatório antes de implementar otimização:

- latência por fase;
- número e bytes de leituras nativas;
- alocações e pico de memória;
- custo com 0, 1, 16 e 128 probes;
- custo de refs por `index` versus `live_scan`;
- x86 e x64.

Não adicionar SIMD, cache global ou dependência externa sem benchmark e nova
revisão de lifetime/invalidação.

## Plano de testes com `SparseFakeSession`

Adicionar um `SparseFakeSession` de teste que mapeie segmentos esparsos por
endereço virtual, em vez de exigir um vetor denso desde zero. Ele deve:

- expor regiões/módulos configuráveis;
- suportar x86/x64 e leituras entre segmentos;
- simular short read, região ausente e erro por endereço;
- contar chamadas/bytes lidos;
- permitir cancelamento determinístico;
- nunca depender de Win32/Linux real.

### Unitários — domínio puro

- busca em intervalos semiabertos, inclusive primeiro/último byte e gaps;
- correlação módulo+RVA e overflow;
- decodificação little-endian x86/x64 e buffer desalinhado;
- `lookbehind` maior que um endereço próximo de zero, sem underflow, e clamp à
  região;
- objeto x64 com campo em `+0x590`, vtable em região de módulo não gravável e
  `K` entradas apontando para regiões executáveis;
- equivalente x86 sem usar bitness do host;
- duas ou mais bases plausíveis produzem candidatos rankeados e
  `field_offset` distintos;
- desempate determinístico;
- qword/dword que aponta para módulo, mas cujas entradas não são executáveis,
  não recebe confiança indevida;
- vtable truncada/short read gera limitação e não entradas sintéticas;
- mínimo de entradas, `K`, probes, evidências e candidatos são respeitados;
- ausência de região/módulo/forma retorna `null`/vazio.

### Application com `SparseFakeSession`

- regiões e módulos são enumerados uma vez por inspeção;
- lookbehind usa uma leitura bounded;
- probes adjacentes são coalescidos sem ler gap não solicitado;
- falha parcial mantém fatos já comprovados e marca `analysis.complete: false`;
- cancelamento para antes do próximo probe/slice e não publica estado tardio;
- detach concorrente mantém lifetime seguro do snapshot/sessão;
- refs por índice validam owner, pointer width, fingerprint, orçamento do build
  e estado stale;
- refs por índice parcial preservam cobertura incompleta;
- live scan respeita orçamento, `resume_token`, retomada e deduplicação;
- resultado vazio completo e vazio incompleto permanecem distinguíveis;
- overflow/limite falha antes de I/O.

### Contrato MCP

- schema exige `session_id`, `address` e `pointer_size`;
- rejeita pointer size inválido, números no lugar de endereço hex, ranges
  invertidos e limites conflitantes;
- `references` usa `oneOf` para `none|index|live_scan`;
- `index_id` com live scan e `byte_budget` com index são rejeitados;
- campos opcionais ausentes usam defaults bounded;
- `null`, arrays vazios, budget, coverage, cursor/`resume_token` e truncation
  serializam exatamente;
- cada candidato contém `classification: probable`, confidence, evidence,
  provenance e `field_offset`;
- resposta nunca excede limites mesmo com milhares de formas/referências;
- contratos legacy/modern mantêm envelope correto.

### Segurança, observabilidade e performance

- logger fake comprova que bytes, endereços, nomes, IDs, cursor e
  `resume_token` não vazam;
- `stdout` contém somente MCP;
- contadores do `SparseFakeSession` comprovam uma enumeração de mapas, uma
  leitura de lookbehind e probes limitados;
- benchmark compara index/live scan e registra ambiente/throughput/alocações;
- ASan e sanitizers aplicáveis cobrem underflow, overflow, short read, lifetime
  e cancelamento.

## Critérios de aceite

- um endereço de campo sintético retorna região/proteções corretas e todos os
  módulos/RVAs calculados sem overflow;
- x86 e x64 produzem o mesmo significado sem depender do host;
- todos os candidatos são explicitamente `probable` e auditáveis por
  confidence/evidence/provenance;
- múltiplas bases plausíveis são devolvidas rankeadas com `field_offset`, sem
  escolher silenciosamente uma única verdade;
- ausência ou leitura insuficiente resulta em `null`/vazio/limitação, nunca em
  dado fabricado;
- lookbehind, probes, `K`, listas, strings e referências obedecem aos tetos;
- `index` e `live_scan` expõem orçamento, cobertura, cursor, completude e
  motivos de truncamento coerentes;
- um vazio de referências só é conclusivo quando a cobertura for completa;
- `SparseFakeSession` confirma I/O bounded e ausência de scan oculto;
- cancelamento, detach e shutdown não deixam thread, sessão ou snapshot vivo
  indevidamente;
- logs não contêm dados de memória e `stdout` permanece protocolo puro;
- nenhuma capacidade proibida ou dependência externa é introduzida.

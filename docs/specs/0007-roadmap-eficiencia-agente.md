# Roadmap — Eficiência do agente em alvo real

Status: em execução — núcleo da Fase 1 concluído em 2026-08-09

## Estado da implementação em 2026-08-09

A parte funcional da Fase 1 está concluída: `scan_first` informa cobertura;
`regions` filtra e pagina; `address_space_summary` agrega o mapa por atributos;
e valores decimais são aceitos em `scan_first` e `scan_next`. A distinção
explícita entre mapeamentos `image` e `mapped` de B2 ainda requer enriquecer o
modelo de região dos providers Windows/Linux e permanece pendente. A rodada
também antecipou otimizações de base:
snapshots COW, candidato inline, batching em `scan_next`/`read_batch`, buffers
reutilizados em scans, uma passagem multi-alvo por profundidade nas cadeias de
ponteiro, JSON limitado/iterativo e catálogo MCP cacheado. IPO/LTO foi medido,
mas permanece opt-in porque perdeu throughput no hot path MCP avaliado.

Continuam planejadas as Fases 2–9: continuação e jobs assíncronos, composição
multipadrão, classificação/inspeção, dimensão temporal, pointer index e
metadata Unreal runtime/savegame. Portanto, os ganhos desta rodada são grandes
e mensuráveis, mas não encerram honestamente o roadmap inteiro.

## Pacote de propostas formalizado em 2026-08-09

Uma auditoria posterior da implementação e do contrato MCP transformou sete
melhorias prioritárias em specs e ADRs próprios. Exceto as Specs 0008, 0011 e
0012 (ver coluna Status), os demais itens desta tabela seguem **propostos,
não implementados**; README e `docs/api/tools.md` só devem anunciá-los como
disponíveis depois da entrega de código e testes.

| Capacidade | Spec | Decisão | Dependência principal | Status |
|---|---|---|---|---|
| Scan completo assíncrono, progresso, cancelamento, continuação e motivo de término | [Spec 0008](0008-async-scan-operations.md) | [ADR-0012](../adr/0012-async-scan-progress-resumption.md) | contrato de cobertura | **implementado** (retomada por `resume_token` é extensão futura) |
| Importação arbitrária de candidatos e multipadrão em uma passagem | [Spec 0009](0009-scan-composition-and-multi-pattern.md) | [ADR-0017](../adr/0017-scan-composition-and-multi-pattern.md) | jobs assíncronos | proposto |
| Índice reutilizável/persistente para pointer chains | [Spec 0010](0010-persistent-pointer-index.md) | [ADR-0018](../adr/0018-persistent-pointer-index.md) | jobs e identidade do processo | proposto |
| Inspeção derivada de endereço, vtable provável e referências | [Spec 0011](0011-inspect-address.md) | [ADR-0013](../adr/0013-address-inspection-derived-evidence.md) | cobertura e pointer index | **implementado**; referências por índice aguardam a Spec 0010 |
| Reflexão Unreal em runtime sem PDB | [Spec 0012](0012-unreal-runtime-reflection.md) | [ADR-0019](../adr/0019-unreal-runtime-reflection.md) | jobs, multipadrão e perfis | **implementado** de forma síncrona; migração para jobs (Spec 0008, já disponível) e descoberta `auto` (Spec 0009) permanecem trabalho futuro |

As três capacidades entregues (0008, 0011 e 0012) preservam o contrato
original: `inspect_address` expõe cobertura e `resume_token` no próprio
slice; as tools Unreal usam o envelope terminal `result` + `termination` com
`execution: "synchronous"`; e os jobs assíncronos da Spec 0008 vivem no
`AnalysisJobManager`, reaproveitando o mesmo motor de scan das tools
síncronas em vez de duplicá-lo. `inspect_address` e as tools Unreal ainda não
migraram para o contrato de jobs — essa migração segue sendo aditiva, não uma
reescrita.

O contrato de jobs é deliberadamente genérico: scans, construção do índice e
enumerações Unreal compartilham lifecycle, backpressure, progresso, paginação,
cancelamento e expiração, sem duplicar pools de workers.

## Motivação

Sessão real de teste do MCP contra `FSD-Win64-Shipping.exe` (Deep Rock Galactic,
PID 3204, 3,24 GB de memória gravável em 18292 regiões), com o objetivo
"encontrar o campo de créditos cujo valor é 91293908".

A tarefa foi concluída — 40 endereços localizados, valor confirmado como a
propriedade `Credits` do save — mas custou **36 chamadas MCP, 4 scripts
PowerShell externos e 3,6 MB de JSON descarregado em arquivo por estourar o
limite de tokens do cliente**. O caminho ótimo para essa mesma tarefa deveria
ser ~7 chamadas e nenhum script.

O gargalo não foi o motor de varredura (que está correto e rápido), e sim o
**contrato das tools**: elas devolvem dados crus na granularidade errada e
delegam ao cliente trabalho analítico que o servidor faria com uma fração do
I/O. Este roadmap ataca especificamente isso.

### Atritos observados

| # | Atrito | Evidência na sessão | Custo |
|---|--------|---------------------|-------|
| 1 | Um scan não cobre o alvo. `max_scan_bytes` tem teto duro de 256 MiB em `policy.cpp:76`; o alvo tinha 3,24 GB graváveis | Primeira chamada varreu ~7% e voltou `candidate_count: 0` | 15 chamadas + cálculo manual de janelas |
| 2 | `scan_first` não reporta cobertura. `ScanSessionInfo` (`types.hpp:122`) só tem `candidate_count` e `generation` | Zero-resultado ambíguo entre "não existe" e "não varri" | 1 chamada perdida + diagnóstico manual |
| 3 | Candidatos ficam presos em N scan sessions isoladas | 15 janelas → 15 `scan_id`, 10 com candidatos | Impossível fazer um `scan_next` único |
| 4 | `regions` não tem filtro, paginação nem agregação | 25561 regiões, 3,5 MB de JSON, estourou tokens | Offload + script para somar bytes graváveis |
| 5 | Classificar candidato exige baixar bytes crus | `read_batch` de 1 KB × 39 = 84 KB de hex | Offload + script de decodificação |
| 6 | Não há classificação de candidato no servidor | Heurísticas de vtable, eco em float e agrupamento escritas à mão em PowerShell | 3 scripts |
| 7 | Não há dimensão temporal | Separar campo estável de buffer transitório exigiu reler os 40 endereços minutos depois e diffar manualmente | 1 rodada extra completa |
| 8 | Leituras não têm carimbo temporal | Baseei uma hipótese num snapshot vencido; o ponteiro já havia mudado quando rodei `scan_pointers_to` | Conclusão errada, depois corrigida |
| 9 | Valor de entrada só em bytes hex little-endian | `91293908` → `d4087105` convertido na mão | Risco de erro silencioso |
| 10 | É preciso escolher o `value_type` antes de varrer | Acertei `i32` no primeiro palpite; se fosse `f32` seria tudo de novo | Potencial 6× do trabalho |

### Lacunas confirmadas pela auditoria posterior

- o transporte mantém uma única tool ativa; cancelamento existe por request,
  mas status/progresso concorrentes recebem `Server busy` e o resultado parcial
  é perdido;
- `scan_exact` reduz orçamento, limite e gaps de leitura a um único
  `truncated`, sem cursor; até o caso “budget exatamente igual ao fim” pode ser
  marcado como truncado;
- `scan_first` já expõe parte da cobertura, mas não há token de continuação nem
  composição dos candidatos de várias janelas;
- pointer chains releem o mapa a cada profundidade e aceitam somente ponteiro
  exatamente igual ao alvo, produzindo offsets intermediários zero;
- as tools Unreal atuais são exclusivamente PDB e a porta de metadata recebe
  caminho de módulo, não uma visão de memória viva.

### Métrica-alvo

Reexecutar a mesma tarefa (mesmo alvo, mesmo valor) medindo:

| Métrica | Baseline desta sessão | Alvo |
|---|---|---|
| Chamadas MCP | 36 | ≤ 8 |
| Scripts externos | 4 | 0 |
| Respostas descarregadas por excesso de tokens | 3 (3,6 MB) | 0 |
| Candidatos entregues ao humano | 40 sem classificação | ≤ 5 grupos classificados |

Conforme `cpp-performance`, nenhuma otimização entra sem baseline registrado
neste formato.

Para as novas fases, cada benchmark/ensaio também registra:

- cobertura (`eligible/scanned/skipped`) e motivo de término, nunca só um
  booleano;
- tempo total, latência de polling/cancelamento e pico de memória retida;
- chamadas e bytes de leitura nativa por sweep — N padrões devem manter
  amplificação de I/O próxima de 1×;
- tempo de build, tamanho e taxa de reuso/revalidação do pointer index;
- itens encontrados/armazenados/retornados e bytes de resposta;
- candidatos de inspeção/Unreal por nível de confiança e invariantes falhas.

## Eixos

### A — Cobertura e orçamento de scan (atritos 1, 2)

- **A1. Continuação segura com `resume_token`.** O serviço ordena as regiões e
  itera internamente. Se não concluir, devolve um token opaco vinculado a
  sessão, mapa, filtros, padrões e carry. O token é o cursor autoritativo:
  endereço isolado não preserva overlap nem gaps de leitura.
- **A1b. `next_start_address` auditável.** Também devolver o primeiro endereço
  lógico alinhado ainda não examinado como hex ou `null`. Ele serve para
  progresso e diagnóstico, não substitui o token. Retomadas preservam
  `max_pattern_size - 1` bytes e deduplicam `{pattern_id,address}` para não
  perder matches em fronteiras.
- **A2. Orçamento por deadline, não por teto de bytes.** O teto de 256 MiB
  protege contra DoS do servidor, mas mede a grandeza errada: o scan já roda em
  chunks com buffer reutilizado, então o consumo de memória é O(chunk), não
  O(byte_budget). Introduzir `deadline_ms` (com `stop_token`, que o motor já
  suporta) como limite primário e manter `max_scan_bytes` apenas como teto
  defensivo elevado. Sem isto, A1 continua exigindo dezenas de continuações.
- **A3a. Cobertura de `scan_first` (implementado).** Expõe bytes/regiões e
  flags de truncagem suficientes para remover o zero-resultado ambíguo nessa
  tool.
- **A3b. Cobertura e término canônicos (proposto).** Generalizar para
  `scan_exact`, multipadrão, referências e pointer chains. Separar
  `coverage_complete` de `results_complete` e expor
  `bytes/regions eligible/scanned`, `matches_found/stored`, gaps e uma lista
  fechada de motivos comuns (`operation_completed`, `range_exhausted`,
  `byte_budget`, `result_limit`, `deadline`, cancelamentos e falhas) estendida
  por variante de operação (`max_depth`, `max_fanout`, `stale_snapshot`,
  `unstable_snapshot`). Estado terminal e motivo não são o mesmo campo;
  `truncated` permanece derivado por compatibilidade.
- **A4. Scan completo assíncrono.** `memory_debug.scan_start` devolve `job_id`
  antes de concluir I/O. Auto-janelamento interno cobre todo o snapshot
  elegível; `memory_debug.job_status`, `job_results`, `job_cancel` e
  `job_release` permanecem responsivos enquanto o worker roda.
- **A5. Lifecycle e backpressure.** Estados monotônicos
  `queued → running → completed|cancelled|failed`, terminais imutáveis,
  progresso monotônico, cancel idempotente, filas/retention bounded, expiração
  de resultado sem reescrever o terminal, workers possuídos e join em
  `detach`/shutdown. Tools síncronas atuais continuam compatíveis.

### B — Consulta de espaço de endereçamento (atrito 4)

- **B1. `regions` ganha filtros e paginação.** `writable`, `readable`,
  `executable`, `private`, `min_size`, `name_contains`, `offset`, `limit`.
- **B2. Nova `memory_debug.address_space_summary`.** Totais e contagens por
  classe (gravável, privada, imagem, mapeada), maior bloco, faixa mínima e
  máxima. Uma resposta de ~20 linhas que responde "quanto há para varrer" —
  exatamente o que precisei e obtive com script.

### C — Composição de scan sessions (atrito 3)

- **C1.** Com A1, `scan_first` passa a devolver **um único `scan_id`** cobrindo
  todo o alvo, publicado somente após cobertura e resultados completos.
  Resolve a causa do atrito sem transformar janela parcial em sessão global.
- **C2. `memory_debug.scan_merge` (deferido).** União de scan sessions continua
  útil, mas não entra neste pacote: compatibilidade de tipo, owner, coverage e
  geração ainda exigem contrato próprio. C3 resolve primeiro o caso necessário
  ao importar a união explícita de endereços.
- **C3. `memory_debug.scan_import`.** Cria scan session a partir de uma lista
  explícita de endereços. O servidor valida overflow, ordena, deduplica e lê o
  baseline atual; bytes fornecidos pelo cliente nunca viram baseline.
  `reject_all` é transacional por padrão e `skip_unreadable` é opt-in, com
  contagens bounded de rejeições. Ownership, geração COW, quotas e teardown são
  os mesmos de uma scan session normal. Endereços só valem para a identidade
  viva da sessão; import não promete portabilidade após restart/PID reuse.
- **C4. `memory_debug.scan_start` / `multi_pattern`.** Aceita IDs estáveis e
  uma lista limitada de valores tipados/padrões binários. Cada chunk do alvo é
  lido uma vez, independentemente da quantidade de padrões; o resultado é
  `{pattern_id,address}` com limites globais e por item. Entradas tipadas podem
  materializar scan sessions-filhas num commit transacional, apenas quando
  cobertura/resultados forem completos; padrões crus retornam só matches.

### D — Classificação de candidatos no servidor (atritos 5, 6) — maior alavancagem

- **D1. `scan_results` com `annotate: true`.** Por candidato, metadados
  **derivados no servidor**, sem trafegar bytes crus:
  - `region`: classe da região e módulo dono, quando houver;
  - `vtable`: primeiro qword alinhado nos N bytes anteriores que aponte para
    região legível/não gravável de módulo e cuja tabela tenha K entradas para
    regiões executáveis, como `{module, rva, distance, evidence}`. É a versão
    fortalecida da heurística que revelou os grupos de objetos com o valor em
    `+0x1C8` e `+0x1F8`;
  - `neighbors`: k dwords antes/depois já decodificados como `i32`/`f32`, com
    marcação de quais formam ponteiro válido para heap ou módulo;
  - `float_echo`: sinaliza quando algum `f32` vizinho está a menos de X% do
    valor — assinatura de contador animado de UI. Foi este sinal
    (`0x4CADD65A` → `0x4CAE211A` entre duas leituras) que separou os 10 widgets
    de exibição do resto;
  - `signature_hash`: hash da vizinhança normalizada, para agrupamento.

  Uma linha por candidato no lugar de 84 KB de hex.

- **D2. `memory_debug.scan_cluster`.** Agrupa por assinatura estrutural
  (vtable + offset, stride de array, `signature_hash`) e devolve apenas os
  grupos, com representante e contagem. Reduz 40 candidatos aos 5 grupos que
  montei manualmente — que é a forma em que a informação é acionável.

  Por `cpp-architecture`, o classificador é função pura sobre um `span<const
  std::byte>` mais o mapa de módulos, no domínio, sem depender de handle de OS
  nem de JSON. Isso o torna unit-testável sem processo vivo (`cpp-testing`).

- **D3. `memory_debug.inspect_address`.** Consolida evidência sobre um endereço:
  região/proteções; módulo dono + RVA; bases de objeto e vtables **prováveis**;
  e referências. A heurística não afirma “vtable” apenas porque um qword aponta
  para código: procura uma base alinhada num lookbehind limitado, exige que o
  primeiro ponteiro caia numa região legível/não gravável de módulo e que K
  entradas da tabela apontem para regiões executáveis. Retorna candidatos
  rankeados, `field_offset`, confiança, evidências e proveniência.

  Referências declaram `source: index|live_scan`, pointer size e cobertura. Sem
  índice, scan ao vivo só ocorre com budget explícito — nunca há full scan
  oculto. Ausência é `null`/array vazio, não hipótese inventada; payload,
  vizinhança e referências são bounded.

### E — Dimensão temporal (atritos 7, 8)

- **E1. `memory_debug.scan_watch`.** Reamostra os candidatos N vezes com
  intervalo e devolve, por candidato, `changed_count`, `stable`, `min`, `max`.
  Separa campo estável de buffer transitório numa única chamada. Duração
  limitada e cancelamento cooperativo via `stop_token`, sem mutex retido
  durante I/O (`cpp-concurrency`).
- **E2. Carimbo temporal em toda leitura.** `sampled_at_ms` monotônico nas
  respostas de leitura e `generation` na scan session, para que o cliente
  detecte que dois resultados não são do mesmo instante. Previne exatamente o
  erro de raciocínio que cometi sobre o ponteiro instável.

### F — Ergonomia de entrada (atritos 9, 10)

- **F1. `value_decimal`.** Para `value_type` numérico, aceitar o valor em
  decimal e deixar o servidor codificar em little-endian. O contrato atual só
  aceita bytes hex, o que empurra conversão manual para o cliente.
- **F2. `value_type: "auto"`.** Varre o mesmo valor decimal como `i32`, `u32`,
  `i64`, `u64`, `f32` e `f64` numa passada só, devolvendo o tipo que casou. O
  custo marginal é próximo de zero porque o gargalo é leitura de memória, não
  comparação (`cpp-performance`).
- **F3. Padrões heterogêneos.** Generaliza F2 para valores e padrões de
  larguras/alinhamentos diferentes, com IDs estáveis, overlaps e carry correto.
  Limites de quantidade, bytes totais e CPU impedem custo
  `O(memória × entrada hostil)` sem controle.

### G — Correlação com metadados de engine (menor prioridade)

- **G1. Leitura de propriedades de savegame Unreal.** O que provou que
  91293908 era `Credits` foi encontrar a propriedade serializada no `.sav` —
  fora do MCP. Um leitor de `nome → tipo → valor` fecharia o ciclo.
  Fica por último: introduz I/O de arquivo, que é superfície nova, e exige ADR
  e gate próprios (`cpp-security`).

- **G2. Reflexão Unreal em runtime sem PDB.** Uma porta separada do provider de
  PDB lê `GUObjectArray`, `FNamePool`, `UObject`/`UClass`/`UStruct` e
  `FField`/`FProperty` por perfis versionados. Faz somente leitura, nenhuma
  chamada de função no alvo, injeção ou remote thread. Counts, chunks, nomes,
  ponteiros, herança, offsets e listas encadeadas passam por bounds, aritmética
  checked e cycle detection. Perfil desconhecido retorna `unsupported`;
  candidato heurístico nunca vira layout confirmado. ADR-0019 estende, mas não
  enfraquece, ADR-0005.

### H — Índice para pointer chains

- **H1. Build assíncrono de índice invertido.** Uma passagem registra pares
  `pointee_value → source_address` e metadados mínimos. Queries usam range
  `[target - max_offset,target]`, permitindo offsets não zero em cada hop, em
  vez de reler toda a memória por profundidade.
- **H2. Snapshot COW e revalidação.** Build publica atomicamente uma geração;
  query concorrente lê snapshot imutável. Toda cadeia retornada é revalidada ao
  vivo; divergências são omitidas e contabilizadas. Falha/cancelamento preserva
  a última geração válida.
- **H3. Persistência opt-in.** Memória é o default. Disco exige gate,
  diretório controlado pelo servidor, ACL do owner, quota/TTL, formato
  versionado, checksum e publicação temp→rename. Identidade inclui PID + tempo
  de criação, pointer size/endianness, fingerprint de módulos e mapa. Índice de
  heap nunca é considerado válido após restart/ASLR; chains normalizadas só
  podem ser reutilizadas após revalidação.

## Ordem de implementação

| Fase | Itens | Risco | Novo gate? | Efeito na métrica-alvo |
|---|---|---|---|---|
| 1 | A3a, B1, B2, F1 | baixo | não | Elimina o zero-resultado ambíguo e os 2 offloads de `regions`; remove conversão hex manual |
| 2 | A1, A1b, A3b | médio | não | Continuação sem lacuna e término inequívoco |
| 3 | A2, A4, A5 | alto | quotas | 15 chamadas de scan → 1 job; progresso/cancelamento reais |
| 4 | C3, C4, F2, F3 | médio | quotas | Une candidatos e evita N passagens para N representações |
| 5 | D1, D2, D3 | médio | budget de refs | Elimina bytes crus/scripts e entrega grupos/evidências |
| 6 | E1, E2 | médio | não | Elimina a rodada manual de reamostragem |
| 7 | H1, H2, H3 | alto | disco opt-in | Reaproveita pointer sweep e produz hops com offsets úteis |
| 8 | G2 | alto | perfis/auto opt-in | Classes e `FProperty` sem depender de PDB |
| 9 | G1 | alto | arquivo opt-in | Correlação com nome de propriedade persistida |

Fases 1–6 são aditivas e somente-leitura, mas jobs mudam o modelo de
concorrência/recursos e exigem quotas próprias. H3 muda a classe de persistência
do servidor e nasce desligado. G2 permanece somente-leitura, porém expõe um
catálogo maior de metadata e exige perfis explicitamente habilitados. G1 muda a
classe de capacidade para leitura de arquivos indicados e também nasce
desligado.

## ADRs necessários

| ADR | Assunto | Fase |
|---|---|---|
| [0012](../adr/0012-async-scan-progress-resumption.md) | Jobs, deadline, progresso, cancelamento e retomada | 2–3 |
| [0013](../adr/0013-address-inspection-derived-evidence.md) | Inspeção derivada e evidência provável | 5 |
| 0014 | Amostragem temporal de candidatos | 6 |
| 0015 | Leitura de metadados de savegame (se a fase 9 for adiante) | 9 |
| [0017](../adr/0017-scan-composition-and-multi-pattern.md) | Importação e composição multipadrão | 4 |
| [0018](../adr/0018-persistent-pointer-index.md) | Índice persistente para pointer chains | 7 |
| [0019](../adr/0019-unreal-runtime-reflection.md) | Reflexão Unreal em runtime sem PDB | 8 |

A3a, B1, B2 e F1 permanecem extensões de contratos existentes. Specs/ADRs
propostos não alteram `docs/api/tools.md`; essa documentação e o threat model
só descrevem comportamento implementado depois de cada entrega.

## Skills aplicáveis

As dez obrigatórias do `AGENTS.md` valem para todas as fases. Além delas:

| Eixo | Skills adicionais | Por quê |
|---|---|---|
| A | `cpp-performance`, `cpp-concurrency` | Baseline e throughput de varredura; deadline, `stop_token`, cancelamento cooperativo |
| B | `cpp-data-structures` | Filtro, ordenação e paginação sobre o vetor de regiões |
| C | `cpp-data-structures` | União e deduplicação de conjuntos de candidatos |
| D | `cpp-data-structures`, `cpp-performance`, `cpp-interop` | Hash de assinatura e agrupamento; evitar releitura redundante; range de módulo vem de API nativa |
| E | `cpp-concurrency`, `cpp-observability` | Amostragem temporizada com shutdown limpo; carimbo temporal e correlação |
| F | `cpp-api-design`, `cpp-memory-safety` | Conversão decimal→bytes é ponto clássico de misuse; largura e sinal precisam ser à prova de erro |
| G | `cpp-security`, `cpp-dependency-management`, `cpp-interop` | Parser de memória hostil, perfis de engine e eventual superfície de I/O/dependência |
| H | `cpp-data-structures`, `cpp-concurrency`, `cpp-performance`, `cpp-security` | Índice invertido, publicação COW, build cancelável, persistência sensível e benchmark |

## Impacto no threat model

Duas mudanças **reduzem** exposição e devem ser registradas como tal: D1 e D2
substituem o tráfego de bytes crus de memória por metadados derivados, e E1
substitui releituras completas por contadores agregados.

Jobs e A2 **aumentam** risco de recurso: trabalho continua depois da resposta
de start e pode reter resultados. Mitigações obrigatórias: workers/jobs globais
e por sessão, deadline e byte budget, cancelamento cooperativo, resultados
bounded/paginados, TTL/release, detach/shutdown com cancel+join e progresso que
não inclui conteúdo.

H3 cria persistência local de metadados sensíveis do layout. Deve ser opt-in,
usar path controlado pelo servidor, ACL do owner, quota/retention, formato
versionado/checksum, publicação atômica e invalidação forte. Nunca persiste
bytes vizinhos. G2 expõe nomes/classes/properties: paginação, filtros, perfis,
proveniência e logs somente com contagens são obrigatórios.

Por `cpp-observability`, nenhuma das novas tools registra conteúdo de memória
em log: `stderr` recebe apenas contagens, durações e identificadores.

## Protocolo de revalidação com valor mutável

O próximo teste do dinheiro será cego, somente-leitura e feito em alvo próprio
ou explicitamente autorizado, preferencialmente offline/solo. O endereço
absoluto da sessão anterior não entra como pista.

1. Anexar `read_only`, registrar PID/identidade, módulos e resumo do espaço.
2. Verificar antes do baseline se a policy comporta todas as janelas
   simultâneas. Para ~3,4 GiB e teto de 256 MiB são cerca de 14 scan sessions;
   o default de 4 não basta. A configuração local de teste usa 64, sem elevar
   o hard cap de 64 nem o limite de candidatos além da policy.
3. O operador estabiliza a UI e informa `V0`; não altera o saldo até a
   confirmação “baseline concluído”.
4. Com o MCP atual, dividir todas as regiões readable+writable (priorizando
   private) em faixas de no máximo 256 MiB elegíveis e executar
   `scan_first(exact,u32,V0)` em cada faixa, exigindo cobertura completa e
   motivo conhecido. Para o saldo positivo testado, `u32` e `i32` têm os
   mesmos quatro bytes; não é necessário reler o alvo para distinguir sinal.
5. Só então o operador faz uma transação legítima no jogo, espera estabilizar
   e informa `V1` e a direção. Rodar `scan_next(exact,V1)` em todos os scans.
6. Repetir com `V2`, idealmente delta diferente e direção oposta. Três
   snapshots reduzem caches, animações e coincidências de UI.
7. Paginar sobreviventes, confirmar com `read_typed` e analisar contexto e
   referências. Calcular base/field offset a partir de evidência; não assumir
   previamente `+0x590`.
8. Fazer detach. Para provar estabilidade, reiniciar a mesma build e repetir:
   endereço absoluto deve poder mudar; offset de campo/cadeia deve se manter e
   ser revalidado. Mudança de build invalida a conclusão.

Depois das propostas, o passo 4 vira um único job completo, hits podem convergir
por `scan_import` e o passo 7 usa `inspect_address`. Registrar por rodada:
chamadas, tempo, bytes/regions eligible/scanned, leituras nativas, candidatos
por geração, cobertura/motivo e bytes de resposta. Não chamar `write`,
`launch`, `terminate` nem tentar contornar proteção/anticheat.

## Fora de escopo

- Escrita habilitada por padrão, injeção de código, criação de thread remota,
  bypass de proteção, ocultação de processo ou captura de credenciais
  continuam proibidos para todos os itens (`AGENTS.md`).
- Nenhum item altera suporte a macOS.
- Nenhum item introduz execução de comando montado com entrada externa.

## Correção de manutenção concluída

As regras para agentes estão em `AGENTS.md`, apontam para o diretório real
`.skills/<skill>/SKILL.md`, e os dois instaladores usam a mesma origem.

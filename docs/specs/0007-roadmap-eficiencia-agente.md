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

Continuam planejadas as Fases 2–5: retomada automática/deadline, classificação
e clustering, dimensão temporal, merge/import e busca multi-tipo. Portanto, os
ganhos desta rodada são grandes e mensuráveis, mas não encerram honestamente o
roadmap inteiro.

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

## Eixos

### A — Cobertura e orçamento de scan (atritos 1, 2)

- **A1. Auto-janelamento com `resume_token`.** O serviço itera as regiões
  internamente até esgotar o alvo. Quando o orçamento da chamada acaba, devolve
  `resume_token` (cursor de endereço opaco) em vez de simplesmente truncar. O
  cliente repete a chamada com o token; não calcula mais janela nenhuma.
- **A2. Orçamento por deadline, não por teto de bytes.** O teto de 256 MiB
  protege contra DoS do servidor, mas mede a grandeza errada: o scan já roda em
  chunks com buffer reutilizado, então o consumo de memória é O(chunk), não
  O(byte_budget). Introduzir `deadline_ms` (com `stop_token`, que o motor já
  suporta) como limite primário e manter `max_scan_bytes` apenas como teto
  defensivo elevado. Sem isto, A1 continua exigindo dezenas de continuações.
- **A3. `ScanSessionInfo` expõe cobertura.** Adicionar `bytes_scanned`,
  `regions_scanned`, `truncated`, `coverage_ratio` e `resume_token`. O dado já
  existe: `scan_pattern_over_regions` calcula `result.truncated` em
  `memory_debug_service.cpp:243` e simplesmente não sobe para o protocolo.
  Elimina de vez o zero-resultado ambíguo.

### B — Consulta de espaço de endereçamento (atrito 4)

- **B1. `regions` ganha filtros e paginação.** `writable`, `readable`,
  `executable`, `private`, `min_size`, `name_contains`, `offset`, `limit`.
- **B2. Nova `memory_debug.address_space_summary`.** Totais e contagens por
  classe (gravável, privada, imagem, mapeada), maior bloco, faixa mínima e
  máxima. Uma resposta de ~20 linhas que responde "quanto há para varrer" —
  exatamente o que precisei e obtive com script.

### C — Composição de scan sessions (atrito 3)

- **C1.** Com A1, `scan_first` passa a devolver **um único `scan_id`** cobrindo
  todo o alvo. Resolve a causa do atrito.
- **C2. `memory_debug.scan_merge`.** União de candidatos de vários `scan_id`,
  para sessões já existentes e para unir varreduras de tipos diferentes.
- **C3. `memory_debug.scan_import`.** Cria scan session a partir de uma lista
  explícita de endereços. Permite retomar trabalho entre reinícios do cliente e
  alimentar o pipeline com endereços vindos de outra fonte.

### D — Classificação de candidatos no servidor (atritos 5, 6) — maior alavancagem

- **D1. `scan_results` com `annotate: true`.** Por candidato, metadados
  **derivados no servidor**, sem trafegar bytes crus:
  - `region`: classe da região e módulo dono, quando houver;
  - `vtable`: primeiro qword alinhado nos N bytes anteriores que caia no range
    executável de um módulo carregado, como `{module, rva, distance}` — é
    literalmente a heurística que reimplementei em PowerShell, e foi ela que
    revelou os grupos de objetos com o valor em `+0x1C8` e `+0x1F8`;
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

### G — Correlação com metadados de engine (menor prioridade)

- **G1. Leitura de propriedades de savegame Unreal.** O que provou que
  91293908 era `Credits` foi encontrar a propriedade serializada no `.sav` —
  fora do MCP. Um leitor de `nome → tipo → valor` fecharia o ciclo.
  Fica por último: introduz I/O de arquivo, que é superfície nova, e exige ADR
  e gate próprios (`cpp-security`).

## Ordem de implementação

| Fase | Itens | Risco | Novo gate? | Efeito na métrica-alvo |
|---|---|---|---|---|
| 1 | A3, B1, B2, F1 | baixo | não | Elimina o zero-resultado ambíguo e os 2 offloads de `regions`; remove conversão hex manual |
| 2 | A1, A2 | médio | não | 15 chamadas de scan → 1; elimina o cálculo de janelas |
| 3 | D1, D2 | médio | não | Elimina os 84 KB de hex e os 3 scripts de classificação |
| 4 | E1, E2 | médio | não | Elimina a rodada manual de reamostragem |
| 5 | C2, C3, F2 | baixo | não | Composição e busca multi-tipo |
| 6 | G1 | alto | sim | Correlação com nome de propriedade |

Fases 1 a 5 são aditivas e somente-leitura, reaproveitam `authorize_scan` e não
alteram a superfície de autorização. A fase 2 é a única que mexe em limite de
recurso e por isso precisa de ADR próprio. A fase 6 muda a classe de capacidade
do servidor (de "ler processos" para "ler arquivos indicados") e deve nascer
desligada.

## ADRs necessários

| ADR | Assunto | Fase |
|---|---|---|
| 0012 | Orçamento de scan por deadline e retomada via `resume_token` | 2 |
| 0013 | Anotação e clusterização de candidatos no servidor | 3 |
| 0014 | Amostragem temporal de candidatos | 4 |
| 0015 | Leitura de metadados de savegame (se a fase 6 for adiante) | 6 |

A3, B1, B2, C2, C3, F1 e F2 são extensões de contrato dentro de decisões já
registradas (ADR-0007, ADR-0009, ADR-0011) e não exigem ADR novo — apenas
atualização de `docs/api/tools.md` e do threat model quando mudarem o que
trafega.

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
| G | `cpp-security`, `cpp-dependency-management` | Superfície de I/O nova; avaliar parser antes de adicionar dependência |

## Impacto no threat model

Duas mudanças **reduzem** exposição e devem ser registradas como tal: D1 e D2
substituem o tráfego de bytes crus de memória por metadados derivados, e E1
substitui releituras completas por contadores agregados.

Uma mudança **aumenta** risco de recurso: A2 eleva o teto de trabalho por
chamada. Mitigações obrigatórias — `deadline_ms` com teto configurável,
cancelamento cooperativo já existente, e backpressure por número de scans
concorrentes (`max_scan_sessions_per_session`).

Por `cpp-observability`, nenhuma das novas tools registra conteúdo de memória
em log: `stderr` recebe apenas contagens, durações e identificadores.

## Fora de escopo

- Escrita habilitada por padrão, injeção de código, criação de thread remota,
  bypass de proteção, ocultação de processo ou captura de credenciais
  continuam proibidos para todos os itens (`AGENTS.md`).
- Nenhum item altera suporte a macOS.
- Nenhum item introduz execução de comando montado com entrada externa.

## Correção de manutenção concluída

As regras para agentes estão em `AGENTS.md`, apontam para o diretório real
`.skills/<skill>/SKILL.md`, e os dois instaladores usam a mesma origem.

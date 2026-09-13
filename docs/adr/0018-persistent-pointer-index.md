# ADR-0018 — Índice invertido persistente de ponteiros

Status: proposto

## Contexto

A [ADR-0011](0011-reverse-pointer-chain-scan.md) e a
[Spec 0006](../specs/0006-pointer-chain-scan.md) automatizaram a BFS reversa e
reduziram cada profundidade a uma passagem multi-alvo. Ainda assim, uma busca
de profundidade `D` relê o espaço elegível até `D` vezes, e o algoritmo exato
só produz hops intermediários zero. Cadeias reais frequentemente acessam um
campo ou subobjeto por offsets não zero.

O caso medido no
[roadmap 0007](../specs/0007-roadmap-eficiencia-agente.md) mostrou que reler
gigabytes e repetir orquestração MCP é o custo dominante em um alvo grande. A
[Spec 0008](../specs/0008-async-scan-operations.md) propõe jobs limitados com
progresso, cancelamento e shutdown determinístico; o build de um índice é uma
operação longa natural para esse modelo.

Persistir o índice pode evitar novo build quando o servidor MCP reinicia e o
mesmo alvo continua vivo. Porém, endereços absolutos de heap não são estáveis
entre execuções do alvo. PID pode ser reutilizado, módulos sofrem ASLR e o mapa
de memória muda. Persistir por nome/hash do executável e rebasing de módulos
seria insuficiente e poderia apresentar cadeia obsoleta como válida.

O contrato detalhado está na
[Spec 0010](../specs/0010-persistent-pointer-index.md). Esta decisão é proposta;
nenhuma capacidade aqui descrita está implementada.

## Decisão

### Índice invertido imutável

O Argos construirá, em uma única passagem por snapshot elegível, arestas
derivadas `{pointed_value, source_address}` para slots de 4 ou 8 bytes cujo
valor aponta para uma região legível. Bytes de memória não serão retidos.

As arestas serão ordenadas por `{pointed_value, source_address}` em um vetor
contíguo e deduplicado. A ordenação permite consulta por faixa com
`lower_bound`, necessária para descobrir `offset = child - pointed_value` sem
enumerar todos os offsets possíveis. Uma tabela auxiliar só será adotada se
benchmark demonstrar ganho.

A query fará BFS reversa sobre o índice. Uma política limitada define offset
assinado mínimo/máximo, alinhamento e inclusão de zero. Ao alcançar uma source
dentro de módulo, a resposta terá `[static_rva, offsets...]` diretamente
compatível com `resolve_pointer_chain`. Profundidade, fanout, faixa de offset,
deadline e resultados terão hard caps; `visited` impedirá ciclos.

### Build assíncrono e snapshots COW

`memory_debug_pointer_index_build` iniciará um job no `AnalysisJobManager` da
Spec 0008. Progresso, resultado terminal, cancelamento e release usarão as
tools genéricas de job. O worker construirá o vetor privadamente, sem mutex de
registry durante leitura, ordenação ou persistência.

Publicação será uma troca curta para
`shared_ptr<const PointerIndexSnapshot>`. Query captura uma referência sob lock
e trabalha fora dele. Substituição, delete ou detach removem a versão do
registry sem invalidar reader já ativo. Cancelamento/falha nunca publica estado
parcial; um build malsucedido preserva a versão anterior.

Não haverá thread destacada. Fila, workers, builds por sessão, memória, arestas,
bytes processados e tempo serão limitados. `detach` e shutdown pedirão stop e
farão join antes de liberar handles.

### Fingerprint forte e validade restrita ao mesmo processo

Cada índice será ligado a:

- PID e creation time do processo;
- plataforma, arquitetura, endianness e pointer size;
- identidade do executável;
- conjunto, identidade, base e tamanho dos módulos;
- mapa ordenado das regiões elegíveis e filtros do build.

O fingerprint será capturado antes e depois do build. Divergência impede
publicação. Query compara novamente a identidade; mismatch retorna
`invalid_state` com reason `stale_index`.

Persistência após restart do MCP é válida somente quando o **mesmo processo**
continua vivo e o fingerprint coincide. Restart do alvo, PID reuse, mudança de
build, ASLR ou mudança do mapa invalidam o índice. A primeira versão não rebasa
arestas de heap nem oferece modo “best effort” entre execuções.

### Revalidação ao vivo

Fingerprint não detecta toda mutação de conteúdo. Por isso cada cadeia será
resolvida novamente na sessão viva antes de ser retornada. Só o resultado que
chegar exatamente ao target receberá `live_confirmed`; null, short-read,
overflow ou divergência serão omitidos e contabilizados. O servidor não
promoverá aresta persistida a evidência atual sem essa leitura.

### Persistência em memória por padrão e disco opt-in

O padrão será índice em memória, com quota e TTL, removido em detach/shutdown.
Disco exigirá gate desligado por padrão e diretório escolhido/canonicalizado
pelo servidor. O request escolherá somente `memory|disk`; nunca path ou nome.

O backend de infraestrutura aplicará ACL/DACL owner-only no Windows ou
diretório `0700`/arquivo `0600` no POSIX, recusando persistência se não puder
garantir as permissões. Symlinks/reparse points e path traversal serão
rejeitados. Haverá quotas por índice, sessão e servidor, TTL e delete por
`index_id` exato; não haverá wildcard/bulk delete na primeira versão.

O formato terá magic, versão, tamanhos, pointer size, endianness, fingerprint,
contagens limitadas, arestas ordenadas e checksum CRC32C. O checksum detecta
corrupção acidental, não substitui ACL nem autentica arquivo hostil. Loader
validará bounds, overflow, ordenação e checksum antes de alocação proporcional.

Publicação em disco usará arquivo temporário exclusivo no mesmo diretório,
permissões restritas, flush e rename atômico. Falha/cancelamento preserva o
artefato anterior e remove o temporário por best effort. Temporários órfãos
expiram por TTL e nunca são carregados como índice.

### API e fronteiras de camada

Serão adicionadas quatro tools:

- `memory_debug_pointer_index_build` — start assíncrono, devolve `job_id`;
- `memory_debug_pointer_index_query` — busca limitada e revalidada por
  `index_id`;
- `memory_debug_pointer_index_list` — metadados paginados e compatibilidade;
- `memory_debug_pointer_index_delete` — remove um ID exato e anuncia
  `destructiveHint: true`.

O build usa `memory_debug_job_status/results/cancel/release` da Spec 0008 e
publica um `index_id` apenas no resultado terminal válido.

Tipos de índice, fingerprint, aresta e algoritmo de query permanecem sem JSON,
filesystem ou handle nativo. `PointerIndexManager` coordena ownership/jobs na
aplicação. Aquisição de creation time, fingerprint nativo, ACL e armazenamento
atômico ficam atrás de portas implementadas na infraestrutura. Protocol/MCP
valida e apresenta os tipos.

Nenhuma dependência externa é escolhida nesta decisão. Uma futura biblioteca
de hashing, compressão ou banco exigirá ADR de dependência, versão/licença e
benchmark; o contrato não dependerá dela.

## Segurança e observabilidade

A leitura do alvo permanece sob autorização existente e nunca habilita escrita,
injeção, thread remota, mudança de proteção, elevação, stealth ou bypass. A
persistência local é a nova superfície de risco e permanecerá opt-in.

Quotas, TTL, fila limitada, cancelamento, parser defensivo, fingerprint,
revalidação, ACL, diretório controlado e publicação atômica mitigam DoS,
vazamento de layout, arquivo hostil, path traversal e confiança obsoleta. O
threat model deve ser atualizado antes da implementação.

Logs estruturados vão somente para `stderr` e contêm IDs opacos, estados,
duração, contagens, storage e motivos seguros. Não contêm endereços, valores de
ponteiro, offsets, cadeias, bytes, paths, fingerprints completos, checksums ou
mensagens nativas cruas. `stdout` continua exclusivo do protocolo.

## Consequências

- o alvo é lido uma vez no build em vez de uma vez por profundidade/query;
- queries repetidas passam a ser CPU/localidade + poucas leituras de validação;
- offsets não zero tornam o resultado diretamente acionável por
  `resolve_pointer_chain`;
- o vetor ordenado favorece range query e formato simples, mas exige pico de
  RAM durante sort e quotas conservadoras;
- snapshots COW simplificam lifetime e concorrência ao custo de a geração
  antiga viver até o último reader;
- um índice pode ficar obsoleto rapidamente num processo que muda o mapa;
  segurança e completude prevalecem sobre reaproveitamento agressivo;
- disco permite reutilização após restart do MCP, mas somente para o mesmo
  alvo vivo, e retém dados derivados sensíveis até TTL/delete;
- delete de cache não altera o alvo, mas é corretamente marcado destrutivo;
- formatos futuros exigirão nova versão e migração explícita, nunca parse
  heurístico.

## Alternativas rejeitadas

### Continuar relendo o alvo por profundidade

É o comportamento seguro atual, mas não amortiza custo entre queries e mantém
I/O `O(depth)` sobre gigabytes.

### `unordered_map` apenas para igualdade exata

É adequado para offset zero, porém offsets configuráveis exigiriam enumerar
cada valor da faixa. O vetor ordenado faz range query sem multiplicar probes.

### Persistir por executável e rebasing de módulo

Não reconstitui heap, não detecta PID reuse e pode validar falsamente uma cadeia
de outra execução. Foi rejeitado em favor de identidade de processo + mapa.

### Persistência em disco por padrão

Criaria retenção silenciosa de layout e escrita local sem decisão do operador.
Memória com TTL é o default; disco exige opt-in explícito.

### Retornar candidatos sem revalidação

Um índice é snapshot e pode ficar velho sem mudança de mapa. Retornar como fato
sem reler a cadeia viola a proveniência exigida pelo projeto.

### Atualização incremental contínua

Exigiria monitorar mudanças, concorrência e invalidação por região de forma
mais complexa. A primeira versão usa rebuild explícito e publicação COW.

### Banco de dados ou formato de terceiros

Não é necessário para um vetor ordenado versionado e aumentaria supply chain,
superfície de parser e acoplamento antes de existir baseline.

## Verificação exigida para aceitação futura

- grafo sintético com ao menos dois offsets não zero resolvendo exatamente o
  target;
- equivalência do índice com scan reverso de referência no snapshot;
- uma passagem por chunk no build e nenhuma full scan durante query;
- cancelamento em scan/sort/persistência, corrida complete × cancel e shutdown;
- COW sob build/query/delete concorrentes, ASan/UBSan e TSan separados;
- fingerprint: mesmo alvo aceito; PID reuse, restart, ASLR, módulo ou mapa
  divergente recusados;
- revalidação filtrando cadeia mutada, null, short-read e overflow;
- round-trip do formato e rejeição de versão, endianness, tamanho, checksum,
  ordenação e arquivo hostil;
- ACL owner-only, gate desligado, quotas, TTL, temp + rename e cleanup;
- contratos build/query/list/delete e jobs nas três eras MCP;
- regressão da Spec 0006 e das tools síncronas;
- warnings elevados, benchmarks documentados e atualização de API, README e
  threat model quando a implementação for entregue.

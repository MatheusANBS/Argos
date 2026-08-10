# Spec 0010 — Índice persistente de ponteiros

Status: proposto · ADR: [0018](../adr/0018-persistent-pointer-index.md)

## Objetivo

Construir uma vez um índice reverso dos ponteiros plausíveis de uma sessão e
consultá-lo muitas vezes para descobrir cadeias até um endereço dinâmico, sem
reler todo o processo a cada profundidade. A consulta deve aceitar offsets
intermediários e finais não zero, dentro de uma faixa configurável e limitada,
e devolver cadeias diretamente verificáveis por `resolve_pointer_chain`.

A proposta complementa o scan reverso da
[Spec 0006](0006-pointer-chain-scan.md) e da
[ADR-0011](../adr/0011-reverse-pointer-chain-scan.md). O build usa o lifecycle
de jobs da [Spec 0008](0008-async-scan-operations.md), e o caso real e as metas
de eficiência vêm do
[roadmap 0007](0007-roadmap-eficiencia-agente.md).

Esta spec é uma proposta. Nenhuma tool, formato ou policy descrita aqui deve
ser anunciada como implementada antes de código, testes e revisão de segurança.

## Lacuna atual

`memory_debug.scan_pointer_chains` faz uma passagem multi-alvo por
profundidade. Isso evita uma passagem por item da fronteira, mas ainda relê o
espaço elegível em cada nível da BFS. Além disso, a busca atual só encontra
referências exatas: os hops não estáticos resultam em zero e o cliente ainda
precisa de uma leitura final para chegar ao alvo.

Uma cadeia real costuma ter a forma:

```text
module_base + static_rva -> P1
P1 + offset_1            -> P2
P2 + offset_2            -> ...
Pn + field_offset        == target
```

Descobrir `offset_1`, `offset_2` e `field_offset` exige consultar ponteiros
cujo valor está próximo — e não necessariamente igual — ao endereço filho. Um
índice invertido ordenado permite fazer essa busca por faixa sem outra varredura
do processo.

## Escopo e não objetivos

Incluído na primeira versão proposta:

- build assíncrono e somente leitura de um índice de ponteiros de 4 ou 8 bytes;
- snapshot imutável em memória por padrão;
- persistência opcional em disco, desligada por padrão;
- busca reversa limitada com offsets assinados configuráveis;
- âncoras em módulos e cadeias prontas para `resolve_pointer_chain`;
- revalidação ao vivo de toda cadeia antes de retorná-la;
- listagem, TTL e exclusão explícita de índices;
- detecção de índice obsoleto, corrompido ou de versão incompatível.

Fora de escopo:

- considerar um índice de heap válido após reinício do processo-alvo;
- rebase automático de arestas de heap após ASLR;
- indexar bytes arbitrários, strings ou valores que não sejam ponteiros
  plausíveis;
- escrever no processo-alvo, injetar código ou chamar funções remotas;
- aceitar diretório ou nome de arquivo fornecido pelo cliente;
- banco de dados externo, serviço remoto ou dependência de runtime nova;
- atualização incremental em background nesta primeira versão.

## Invariantes

1. Todo índice pertence a uma identidade de processo e a um snapshot de mapa de
   memória, não apenas a um PID ou nome de executável.
2. O builder lê o alvo; o índice publicado nunca contém bytes brutos, somente
   arestas derivadas e metadados limitados.
3. Build, serialização e consulta não mantêm mutex de registry durante I/O do
   processo, I/O de arquivo, ordenação extensa ou espera de worker.
4. Um índice só é publicado como `shared_ptr<const PointerIndexSnapshot>`; uma
   consulta nunca observa vetor em mutação.
5. Cancelamento ou falha não publica um índice parcial. Truncagem normal só
   pode publicar snapshot parcial quando `allow_partial: true`; disco exige
   índice completo.
6. Toda cadeia retornada como válida foi reexecutada contra a sessão viva e
   resolveu exatamente o `target_address` solicitado.
7. Persistência em disco exige gate, diretório e quotas definidos pelo servidor.
8. `stdout` contém exclusivamente MCP/JSON-RPC; logs ficam em `stderr` e não
   contêm endereços, arestas, offsets, bytes ou caminhos internos.

## Modelo de dados

Tipos de domínio propostos, sem JSON, filesystem, logging ou handles nativos:

```cpp
class PointerIndexId final { /* identificador opaco validado */ };

enum class TargetEndianness { little, big };
enum class PointerIndexCompleteness { complete, partial };

struct ProcessFingerprint {
    ProcessId pid{};
    std::uint64_t creation_time{};
    std::array<std::byte, 32> module_set_hash{};
    std::array<std::byte, 32> eligible_map_hash{};
    std::array<std::byte, 32> executable_identity_hash{};
};

struct PointerEdge {
    Address pointed_value{}; // chave do índice invertido
    Address source_address{};
};

struct PointerOffsetPolicy {
    std::int64_t minimum{};
    std::int64_t maximum{};
    std::uint64_t alignment{1};
    bool include_zero{true};
};

struct IndexedPointerChain {
    std::string module_name;
    Address module_base{};
    std::uint64_t static_rva{};
    std::vector<std::int64_t> offsets;
    Address resolved_address{};
};

enum class PointerIndexPhase { scanning, sorting, persisting, publishing };

struct PointerIndexProgress {
    std::uint64_t sequence{};
    PointerIndexPhase phase{};
    std::size_t bytes_processed{};
    std::size_t bytes_eligible{};
    std::size_t regions_processed{};
    std::size_t regions_eligible{};
    std::size_t edges_found{};
    std::size_t edges_retained{};
};

struct PointerIndexJobResult {
    PointerIndexId index_id;
    PointerIndexCompleteness completeness{};
    std::size_t edge_count{};
    std::size_t retained_bytes{};
};
```

O provider nativo deve fornecer `creation_time` em representação estável para
comparação na mesma plataforma. O fingerprint de módulos inclui, de forma
canônica e hasheada, identidade do executável, conjunto de módulos, bases,
tamanhos e identificadores de imagem disponíveis. O fingerprint do mapa inclui
as regiões elegíveis ordenadas, faixas, proteções, classe e associação com
módulo. Caminhos completos não entram no contrato público nem nos logs.

O índice é um vetor contíguo de `PointerEdge`, ordenado por
`{pointed_value, source_address}` e deduplicado. Essa forma favorece localidade,
serialização e consulta por `lower_bound`. Uma tabela auxiliar por página ou
prefixo pode ser adicionada após benchmark, mas não muda a semântica.

## Build do índice

### Seleção de arestas

O builder captura, no início, os módulos, as regiões elegíveis e o fingerprint
`F0`. Em uma passagem:

1. lê cada região elegível em chunks reutilizáveis;
2. decodifica slots alinhados segundo `pointer_size` e endianness do alvo;
3. descarta nulo, valor não representável e valor que não cai em uma região
   legível do snapshot;
4. armazena `{pointed_value, source_address}` sem conservar o buffer lido;
5. aplica limites de bytes, arestas e memória retida;
6. ordena e deduplica as arestas em memória privada do job.

Antes da publicação, o serviço recalcula o fingerprint `F1`. Se `F1 != F0`, o
build termina como `failed/stale_snapshot`; ele não publica uma visão que
mistura dois mapas. Mudanças apenas nos valores dos slots, que não alteram o
mapa, são tratadas pela revalidação live da consulta.

O custo de I/O deve ser uma passagem pelo snapshot elegível, salvo fallback
explícito de short-read. O build não faz uma passagem por target nem por
profundidade.

### Job assíncrono e publicação COW

`memory_debug.pointer_index_build` apenas valida/admite o pedido e devolve um
`job_id`. Execução, progresso, cancelamento, TTL e release usam o
`AnalysisJobManager` e as tools genéricas da Spec 0008:

- `memory_debug.job_status`;
- `memory_debug.job_results`;
- `memory_debug.job_cancel`;
- `memory_debug.job_release`.

O job constrói um vetor mutável privado. A publicação terminal faz uma única
troca no `PointerIndexManager`, sob lock curto, para um
`shared_ptr<const PointerIndexSnapshot>`. Ao substituir um índice compatível,
leitores que já capturaram o snapshot antigo terminam com segurança; consultas
novas veem somente a nova geração. O índice anterior permanece publicado se o
novo build falhar, for cancelado ou não puder ser persistido.

`detach` cancela builds `queued`/`running` da sessão e aguarda os workers
conforme a Spec 0008. Índices somente em memória pertencentes à sessão são
removidos do registry; readers que já possuem snapshot mantêm lifetime seguro
até a última referência. Índices em disco não dão lifetime ao handle do alvo.

## Consulta reversa com offsets não zero

Para um endereço filho `C` e uma aresta `{P, S}`, o hop é válido quando:

```text
offset = C - P
minimum <= offset <= maximum
offset é múltiplo de alignment
offset != 0 quando include_zero == false
```

Toda subtração e toda reconstrução de endereço verifica overflow/underflow e
representabilidade em `int64_t`. Como as arestas estão ordenadas por `P`, a
consulta usa a faixa `[C - maximum, C - minimum]`, limitada ao domínio de
endereços, e filtra o alinhamento sem enumerar todos os offsets possíveis.

A BFS reversa começa em `target_address`. Cada aresta encontrada produz o
próximo filho `S` e acumula o offset calculado. Ao alcançar uma
`source_address` dentro de um módulo, ela vira âncora. A cadeia retornada contém:

```text
[static_rva, offset_1, ..., field_offset]
```

e deve resolver diretamente para o target pelo contrato atual de
`resolve_pointer_chain`, sem o “deref extra” exigido pelo resultado da Spec
0006. Exemplo sintético:

```text
*(module + 0x10) == 0x2000
*(0x2000 + 0x20) == 0x3000
0x3000 + 0x590 == 0x3590

offsets retornados: [0x10, 0x20, 0x590]
```

`max_depth`, `max_fanout`, `result_limit`, faixa absoluta máxima de offset e
deadline da consulta têm hard caps. `visited` impede ciclos. O resultado
distingue truncagem por profundidade, fanout, resultados, deadline e índice
parcial. A consulta nunca apresenta ausência de cadeia em índice parcial como
prova de inexistência.

### Revalidação live

Antes de retornar cada candidato, o serviço:

1. confere novamente a identidade/fingerprint atual;
2. obtém a base atual do módulo âncora;
3. executa a cadeia inteira, lendo cada ponteiro da sessão viva;
4. rejeita null, short-read, overflow ou divergência;
5. só marca `live_confirmed` quando o resultado é exatamente o target pedido.

O padrão é omitir candidatos que falharam e informar apenas contagens
`stale_candidates`/`validation_failures`. Não existe opção para promover um
candidato não verificado a confirmado. Uma futura opção diagnóstica para
retornar candidatos não verificados exigirá contrato e threat-model próprios.

## Identidade, staleness e ASLR

Compatibilidade exige igualdade de:

- plataforma/arquitetura e endianness;
- `pointer_size`;
- PID e creation time;
- identidade do executável e fingerprint do conjunto de módulos;
- bases/tamanhos dos módulos;
- fingerprint do mapa de regiões elegíveis;
- filtros usados no build.

PID sozinho é insuficiente porque pode ser reutilizado. Nome ou hash do
executável também é insuficiente: uma nova execução possui heap diferente.

Um índice em disco pode ser reutilizado depois de reiniciar o MCP somente se o
mesmo processo-alvo continuar vivo e todos os campos acima coincidirem. Após
reiniciar o alvo, ASLR e novas alocações invalidam arestas absolutas de heap; o
índice recebe `stale` e a query retorna `invalid_state` com reason
`stale_index`. A primeira versão não
rebasa nem tenta “salvar” apenas as âncoras de módulo, pois isso produziria
confiança falsa sobre hops intermediários.

Mudanças no mapa depois do build invalidam completude, mesmo que algumas
arestas antigas ainda revalidem. Mudanças de conteúdo com mapa estável são
esperadas e filtradas pela revalidação live.

## Persistência

### Memória por padrão

Sem configuração adicional, `storage: "memory"` é a única opção aceita. O
snapshot expira por TTL, conta contra quota total e desaparece em `detach` ou
shutdown. Isso preserva o comportamento read-only no filesystem.

### Disco somente opt-in

`storage: "disk"` exige cumulativamente:

- gate de ambiente dedicado, desligado por padrão;
- diretório configurado pelo operador e canonicalizado pelo servidor;
- diretório não controlado pelo request e sem symlink/reparse point aceito;
- ACL/DACL restrita ao usuário dono no Windows, ou diretório `0700` e arquivo
  `0600` no POSIX; se a restrição não puder ser aplicada, falha fechada;
- quotas por índice, por sessão e globais, mais TTL máximo;
- índice completo e fingerprint terminal estável.

O cliente escolhe apenas `memory` ou `disk`; nunca envia path, filename ou
fragmento de path. Nomes derivam exclusivamente de `index_id` opaco validado.
Policies propostas devem limitar contagem de índices, builds concorrentes,
arestas, bytes de RAM, bytes em disco, TTL e tamanho de arquivos temporários.
Defaults e hard caps precisam ser definidos a partir do benchmark antes da
aceitação da implementação.

### Formato v1 proposto

O artefato possui:

- magic fixo e `format_version`;
- comprimento do header e de cada seção;
- endianness canônica do arquivo e endianness do alvo;
- `pointer_size`, plataforma e arquitetura;
- contagem de arestas e tamanhos totais;
- timestamps de criação/expiração;
- fingerprint completo e hash dos filtros;
- arestas ordenadas em representação de largura fixa;
- identificador do algoritmo e checksum CRC32C de header normalizado e payload.

CRC32C detecta corrupção acidental; não é MAC e não autentica um atacante com
acesso de escrita ao diretório. A segurança contra alteração local depende das
permissões owner-only e da validação defensiva do parser.

O loader valida versão, flags conhecidas, larguras, contagens, multiplicações,
offsets de seção, tamanho exato do arquivo, ordenação e checksum **antes** de
alocações proporcionais ao conteúdo. Versão desconhecida retorna `unsupported`
com reason `unsupported_index_version`; checksum/layout inválido retorna
`parse_error` com reason `corrupt_index`; fingerprint divergente retorna
`invalid_state` com reason `stale_index`. Nenhum desses casos cai para uma
tentativa heurística de parse.

### Publicação atômica

O writer cria arquivo temporário exclusivo no mesmo diretório, aplica
permissões, escreve com RAII e limite, finaliza checksum, faz flush e publica
por rename atômico. Não sobrescreve um artefato válido por conteúdo parcial.
Falha ou cancelamento remove o temporário por best effort e preserva a versão
anterior. Na inicialização/listagem, temporários órfãos expiram por TTL e nunca
são carregados como índices.

## Contratos MCP

Todos os endereços são strings hexadecimais. `index_id` e `job_id` são opacos.
Erros de owner retornam `not_found`, sem revelar índice de outra sessão.

### `memory_debug.pointer_index_build`

```json
{
  "session_id": "session_…",
  "pointer_size": "8",
  "writable_only": false,
  "storage": "memory",
  "ttl_ms": 900000,
  "allow_partial": false
}
```

Resposta imediata:

```json
{
  "ok": true,
  "data": {
    "job_id": "job_…",
    "job_kind": "pointer_index",
    "operation": "pointer_index_build",
    "state": "queued"
  }
}
```

`job_status` expõe progresso monotônico com bytes/regiões elegíveis e
processados, arestas plausíveis encontradas/retidas, memória aproximada e fase
`scanning|sorting|persisting|publishing`. O resultado terminal contém
`index_id`, fingerprint público reduzido, completude, cobertura, contagem de
arestas, storage, tamanho retido e expiração. Cancelamento/falha não contém
`index_id` novo.

### `memory_debug.pointer_index_query`

```json
{
  "session_id": "session_…",
  "index_id": "pidx_…",
  "target_address": "0x1FE44726C90",
  "max_depth": 6,
  "max_fanout": 16,
  "result_limit": 32,
  "offset_policy": {
    "minimum": 0,
    "maximum": 4096,
    "alignment": 4,
    "include_zero": true
  }
}
```

Resposta limitada:

```json
{
  "ok": true,
  "data": {
    "index_id": "pidx_…",
    "index_complete": true,
    "chains": [
      {
        "module": "Game.exe",
        "module_base": "0x7FF7F4000000",
        "static_rva": "0x14010",
        "offsets": [81936, 32, 1424],
        "resolved_address": "0x1FE44726C90",
        "validation": "live_confirmed"
      }
    ],
    "stale_candidates": 3,
    "truncated": false,
    "stop_reason": "search_exhausted"
  }
}
```

`minimum`/`maximum` são assinados, `minimum <= maximum`, `alignment` é potência
de dois e a faixa absoluta não pode exceder a policy. `include_zero: false`
força hops dinâmicos não zero. O primeiro item de `offsets` é sempre o RVA
estático e não é filtrado pela política de offsets dinâmicos.

### `memory_debug.pointer_index_list`

```json
{
  "session_id": "session_…",
  "storage": "all",
  "offset": 0,
  "limit": 50
}
```

Retorna página de metadados pequenos: `index_id`, geração, pointer size,
endianness, storage, completude, edge count, bytes, criação, expiração e
`compatibility: compatible|stale|corrupt|unsupported_version`. Não retorna
arestas, endereços, paths nem checksum bruto. Artefato incompatível não é
carregado em memória só para ser listado.

### `memory_debug.pointer_index_delete`

```json
{
  "session_id": "session_…",
  "index_id": "pidx_…"
}
```

Remove exatamente um índice do registry e, se existir, seu artefato controlado.
Não aceita wildcard, path ou “delete all”. A tool anuncia
`destructiveHint: true`, embora não altere o processo-alvo. Uma query que já
capturou snapshot COW pode terminar; novas queries recebem `not_found`.
Resposta informa apenas `memory_removed` e `disk_removed`.

Índice em build ainda não possui `index_id` publicado e deve ser cancelado pelo
`job_id`; delete não cancela implicitamente um job.

## Erros

- `invalid_argument`: pointer size, range, alinhamento, paginação ou storage
  inválido;
- `not_found`: sessão/índice inexistente ou owner divergente;
- `limit_exceeded`: quota, TTL, arestas, memória, disco, profundidade, fanout,
  offset ou resultados acima da policy;
- `access_denied`: persistência em disco desabilitada ou permissões owner-only
  indisponíveis;
- `invalid_state`: build incompatível, índice ainda não publicado ou conflito
  de substituição;
- `invalid_state` / `stale_index`: fingerprint atual diverge do
  artefato/snapshot;
- `parse_error` / `corrupt_index`: formato, tamanho, ordenação ou checksum
  inválido;
- `unsupported` / `unsupported_index_version`: versão, plataforma ou
  endianness não suportada;
- `cancelled`: cancelamento cooperativo do build;
- `io_error`: erro seguro de leitura ou persistência, sem mensagem nativa crua.

## Segurança e threat model

O índice não adiciona escrita no alvo, mas disco opt-in adiciona uma nova
superfície de escrita local e retenção de endereços derivados. Antes de
implementar, o threat model deve incluir:

- exaustão de CPU, RAM e disco durante build/ordenação;
- path traversal, symlink/reparse point e permissões herdadas;
- arquivo hostil, integer overflow e alocação controlada pelo header;
- vazamento de layout por artefato, listagem ou log;
- PID reuse e confiança indevida após restart/ASLR;
- corrida build/query/delete/detach/shutdown;
- temporário órfão e falha entre flush e rename.

Mitigações obrigatórias: autorização da sessão existente, mesmo usuário por
padrão, gate de disco, diretório do servidor, ACL owner-only, quotas, TTL,
parser limitado, checksum, fingerprint forte, publicação atômica, COW,
cancelamento cooperativo e revalidação live.

Não registrar conteúdo de ponteiros, endereços, offsets, fingerprint completo,
paths, nomes de arquivo, checksum ou cadeia. Não aceitar shell, comandos,
injeção, remote thread, mudança de proteção, elevação, stealth ou bypass.

## Observabilidade

Logs estruturados em `stderr` podem conter:

- `job_id`/`index_id` opacos;
- estado/fase e motivo de término;
- contagens agregadas de regiões, bytes e arestas;
- duração, throughput agregado e tamanho retido;
- storage como `memory|disk` e resultado genérico de validação/cleanup.

Não logar dados listados na seção de segurança. Cleanup por TTL, exclusão,
staleness, corrupção, cancelamento e falha de publicação devem ser distinguíveis
por evento/código seguro. `stdout` permanece reservado ao protocolo.

## Performance

Baseline obrigatório antes de escolher defaults:

- tamanho elegível, regiões e pointer size;
- bytes/s e chamadas nativas durante build;
- arestas antes/depois de deduplicação;
- pico de RAM durante scan e sort;
- tamanho serializado e tempo de load/save;
- latência de query por profundidade/faixa/fanout;
- leituras live por cadeia confirmada;
- latência de cancelamento e impacto no alvo.

Critérios estruturais:

- build faz no máximo uma leitura de cada chunk elegível, salvo short-read;
- query não dispara full scan e faz `O(log E + hits)` por nó visitado, onde
  `E` é o número de arestas;
- revalidação lê no máximo `O(depth)` ponteiros por candidato;
- buffers são reutilizados e arestas ficam contíguas;
- nenhuma otimização SIMD, compressão complexa ou dependência externa entra
  sem benchmark comparável de correção, throughput, RAM e disco.

## Plano de testes

### Unidade — índice e busca

- ordenação/deduplicação de `{pointed_value, source_address}`;
- ponteiros 32/64-bit, endianness e slots alinhados;
- descarte de null, alvo fora do mapa e overflow;
- range query em offsets mínimo/máximo, positivo, negativo, zero incluído e
  zero excluído;
- alinhamento de offset e faixa cruzando `0`/`UINT64_MAX` sem UB;
- grafo sintético `module+0x10 -> 0x2000`, `0x2000+0x20 -> 0x3000`,
  `0x3000+0x590 == target`, esperando `[0x10,0x20,0x590]`;
- branching, ciclos, duplicatas, depth/fanout/result limit e motivos;
- cadeia retornada reproduz exatamente o target via `resolve_pointer_chain`;
- índice parcial nunca sustenta conclusão negativa de busca.

### Unidade — jobs, COW e lifetime

- start retorna antes do I/O terminar e progresso não regride;
- cancelar em `queued`, scan, sort e persistência não publica índice;
- corrida conclusão × cancelamento tem um único terminal;
- build novo publica por troca e reader antigo conserva snapshot estável;
- falha/cancelamento preserva snapshot anterior;
- delete concorrente remove discoverability sem UAF do reader;
- detach e shutdown cancelam/joinam workers, sem handle/thread/temporário órfão;
- nenhum mutex fica retido durante read, sort, file I/O ou join;
- ASan/UBSan e TSan em builds separadas.

### Fingerprint e revalidação

- mesma sessão/processo/fingerprint aceita query;
- mesmo PID com creation time diferente é stale;
- módulos iguais com base, tamanho ou identidade diferente são stale;
- mapa ou filtros diferentes são stale;
- restart do MCP com o mesmo alvo vivo aceita artefato compatível;
- restart do alvo/ASLR recusa o índice, mesmo com executável idêntico;
- mutação de uma aresta com mapa estável é filtrada na revalidação;
- short-read/null/overflow durante validação não retorna falso confirmado.

### Formato e filesystem

- round-trip determinístico do formato v1 em 32/64-bit;
- magic, versão, endianness, pointer size, flags e checksum inválidos;
- arquivo truncado, trailing bytes, contagem hostil, soma/multiplicação com
  overflow, seção sobreposta e arestas fora de ordem;
- fuzz do loader com alocação limitada;
- gate de disco desligado por padrão e request sem suporte a path;
- ACL/DACL owner-only validada por integração de plataforma;
- symlink/reparse point e diretório fora da configuração são recusados;
- falha/cancelamento antes do rename deixa índice anterior válido;
- rename publica arquivo completo; temporário órfão expira por TTL;
- quota por índice/global, TTL mínimo/máximo e cleanup;
- delete remove apenas o `index_id` exato.

### Contrato MCP

- build/query/list/delete têm `inputSchema` e `outputSchema` completos nas três
  eras MCP da ADR-0016;
- build integra `job_status/results/cancel/release` da Spec 0008;
- campos ausentes, tipos errados, offset invertido, alignment inválido,
  storage inválido e paginação extrema;
- owner divergente retorna `not_found` e não revela metadados;
- disk sem gate retorna `access_denied` antes de criar temporário;
- list não expõe path, fingerprint completo ou arestas;
- delete anuncia `destructiveHint: true` e rejeita wildcard/path;
- tools atuais da Spec 0006 permanecem byte-a-byte compatíveis.

### Integração e performance

- provider instrumentado confirma uma passagem por chunk no build;
- query repetida não relê o espaço todo e coincide com scan reverso de
  referência no snapshot;
- alvo controlado com cadeia de offsets não zero produz resultado confirmado;
- persistência opt-in sobrevive a restart do MCP com o alvo vivo;
- restart do alvo transforma o mesmo artefato em stale;
- benchmarks registram as métricas desta spec em MSVC, Clang e GCC quando
  suportados, com warnings elevados e sanitizers aplicáveis.

## Critérios de aceite

- build é assíncrono, cancelável, limitado e lê cada chunk elegível uma vez;
- o índice invertido encontra e revalida ao menos uma cadeia com dois offsets
  não zero, pronta para `resolve_pointer_chain`;
- offsets assinados, faixa, alignment, depth, fanout e resultados obedecem hard
  caps e não causam overflow;
- snapshots são COW/imutáveis; build, query, delete, detach e shutdown não
  causam corrida, deadlock, UAF ou thread/handle órfão;
- memória é o storage padrão e disco falha fechado sem opt-in;
- artefato em disco é owner-only, limitado, versionado, checksummed e publicado
  por temp + rename atômico;
- stale, corrupt e versão incompatível são estados distintos e seguros;
- o mesmo processo pode reutilizar índice após restart do MCP, mas restart do
  alvo/ASLR nunca reutiliza arestas de heap silenciosamente;
- toda cadeia retornada é `live_confirmed`; divergências são omitidas e
  contabilizadas;
- list/delete/TTL/quota funcionam sem paths do cliente ou exclusão ampla;
- nenhum byte bruto ou dado sensível entra no índice, logs ou `stdout`;
- testes unitários, contrato, integração, warnings e sanitizers aplicáveis
  passam antes de mudar o status para aceito;
- API, README e threat model só anunciam a capacidade quando a implementação
  correspondente for entregue.

## Referências internas

- [Spec 0006 — `memory_debug.scan_pointer_chains`](0006-pointer-chain-scan.md)
- [ADR-0011 — Scan reverso de cadeia de ponteiros](../adr/0011-reverse-pointer-chain-scan.md)
- [Spec 0008 — Operações assíncronas de scan](0008-async-scan-operations.md)
- [Roadmap 0007 — Eficiência do agente em alvo real](0007-roadmap-eficiencia-agente.md)
- [ADR-0018 — Índice invertido persistente de ponteiros](../adr/0018-persistent-pointer-index.md)
- [Threat model — depuração de memória em runtime](../threat-model/runtime-memory-debug.md)

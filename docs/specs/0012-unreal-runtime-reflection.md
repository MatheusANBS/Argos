# Spec 0012 — Reflexão Unreal em runtime sem PDB

Status: proposto · ADR: [0019](../adr/0019-unreal-runtime-reflection.md)

## Objetivo

Enumerar, de forma somente-leitura e com proveniência explícita, os objetos,
classes e propriedades que o runtime Unreal mantém em `GUObjectArray`,
`FNamePool`, `UClass`/`UStruct` e `FProperty`, mesmo quando o PDB da build não
está disponível.

A capacidade complementa — não substitui — `memory_debug.unreal_type` e
`memory_debug.unreal_reflection`. O caminho PDB continua sendo a fonte mais
forte para layout nativo; o caminho runtime só reporta o que um perfil
suportado e validações estruturais conseguirem demonstrar.

## Escopo e não objetivos

Incluído:

- perfis explícitos para famílias de layout Unreal suportadas;
- raízes explícitas, por perfil/build ou candidatas por assinatura;
- enumeração paginada de slots vivos, classes, herança e propriedades;
- `FField`/`FProperty` para perfis modernos e `UField`/`UProperty` somente em
  perfil legado separado;
- proveniência, evidências, confiança e detecção de snapshot instável;
- jobs, progresso, cancelamento, limites e teardown.

Fora de escopo:

- prometer suporte automático a qualquer UE4, UE5, fork ou build futura;
- chamar `StaticClass`, `ProcessEvent` ou qualquer função no alvo;
- injetar DLL/código, criar thread remota, alterar proteção ou escrever;
- descriptografar/contornar ofuscação ou mecanismos de proteção;
- inferir campos nativos não refletidos como se fossem `UPROPERTY`;
- ler valores de todas as instâncias por padrão;
- promover uma signature ou string plausível a layout confirmado.

## Dependências entre propostas

- [Spec 0008](0008-async-scan-operations.md): jobs, progresso,
  cancelamento, paginação e expiração;
- [Spec 0009](0009-scan-composition-and-multi-pattern.md): descoberta
  opcional das raízes em uma única passagem;
- [Spec 0011](0011-inspect-address.md): evidências de região/módulo para
  endereços candidatos;
- [ADR-0005](../adr/0005-engine-metadata-provenance.md): contrato atual de
  proveniência PDB que esta proposta estende.

Nenhuma dessas propostas autoriza acesso a um processo que a policy atual não
permitiria anexar.

## Arquitetura

### Porta de leitura runtime

`TypeMetadataProvider` atual recebe um arquivo/módulo e não deve ser ampliado
para esconder uma sessão de processo. A proposta introduz uma porta própria:

```cpp
struct RuntimeAddressSpaceSnapshot {
    ProcessIdentity identity;
    std::vector<MemoryRegion> regions;
    std::vector<ModuleInfo> modules;
    std::uint64_t sequence{};
    std::chrono::steady_clock::time_point sampled_at;
};

class RuntimeMemoryView {
public:
    virtual ~RuntimeMemoryView() = default;
    [[nodiscard]] virtual Result<ReadResult> read(
        Address address,
        std::span<std::byte> destination,
        std::stop_token cancellation) const = 0;
    [[nodiscard]] virtual Result<
        std::shared_ptr<const RuntimeAddressSpaceSnapshot>> snapshot() const = 0;
};
```

O adapter de aplicação projeta uma `ProcessSession` autorizada nessa interface.
Parsers recebem `RuntimeMemoryView` ou buffers já lidos, nunca JSON, handles
nativos ou paths arbitrários. O snapshot possui seus vetores e identidade por
todo o job/query; nenhum `span` aponta para storage atualizável após detach ou
refresh. Aritmética de endereço usa helpers checked.

### Perfil de layout

```cpp
struct UnrealRuntimeProfile {
    std::string id;
    std::string engine_family;
    std::size_t pointer_size;
    Endianness endianness;
    ObjectArrayLayout object_array;
    NamePoolLayout name_pool;
    UObjectLayout uobject;
    UStructLayout ustruct;
    PropertyLayout property;
    ProfileLimits hard_limits;
};
```

Cada perfil é imutável, versionado e habilitado explicitamente no build do
MCP. Ele declara todos os offsets usados pelo parser, inclusive serial number,
chunk size, `ClassPrivate`, `NamePrivate`, `SuperStruct`, cabeça/next da lista
de properties, `Offset_Internal`, `ElementSize`, `ArrayDim` e flags aplicáveis.

Um perfil não é selecionado apenas por uma string informada pelo cliente. A
abertura valida pointer size/endianness, identidade/fingerprint do módulo e
invariantes próprias do perfil. Perfil desconhecido ou incompatível resulta
em `DebugErrorCode::unsupported` com `reason: "unsupported_profile"`.

Perfis de UE4 com `UProperty` e perfis com `FField/FProperty` não compartilham
offsets por fallback. Cada parser é selecionado explicitamente pelo perfil.

### Contexto validado

```cpp
enum class DiscoveryMode { explicit_roots, build_profile, auto_discovery };
enum class RootOrigin {
    explicit_rva,
    explicit_address,
    build_profile,
    signature_candidate
};
enum class RuntimeConfidence { low, medium, high };

struct UnrealRuntimeContext {
    RuntimeId id;
    SessionId owner;
    ProcessIdentity identity;
    std::string profile_id;
    Address gu_object_array;
    Address fname_pool;
    RootOrigin root_origin;
    RuntimeConfidence confidence;
    std::vector<Evidence> evidence;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point expires_at;
    std::size_t retained_bytes{};
};
```

O `runtime_id` referencia configuração e catálogos derivados, não um handle
nativo nem garantia de snapshot permanente. Ele pertence à sessão; `detach`,
expiração, mudança de identidade ou `unreal_runtime_release` o invalidam.

### Jobs e recursos derivados

Descoberta e enumeração extensa acrescentam `AnalysisJobKind::unreal_runtime`
e variantes fechadas `UnrealRuntimeProgress`/`UnrealRuntimeJobResult` ao
contrato da Spec 0008. Starts específicos devolvem `job_id`; status, paginação,
cancelamento e liberação usam exclusivamente:

- `memory_debug.job_status`;
- `memory_debug.job_results`;
- `memory_debug.job_cancel`;
- `memory_debug.job_release`.

Todos entram no mesmo `AnalysisJobManager`, fila, quotas e pool de
`std::jthread` usado por scans e pointer-index. Não existe pool, detached thread
ou registry de jobs próprio do adapter Unreal. `job_release` libera o payload
do job, mas **não** apaga um `runtime_id` já publicado; este possui quota, TTL e
release próprios.

## Descoberta e validação

### Modos

`explicit`
: O cliente fornece módulo + RVA para as duas raízes. Endereços absolutos são
  aceitos apenas para a sessão corrente e nunca persistidos como build profile.

`profile`
: O servidor usa RVAs vinculados a um fingerprint de módulo conhecido. Base
  fresca + RVA é calculada com overflow checked.

`auto`
: Um job multipadrão procura signatures cadastradas somente nos módulos
  autorizados. Cada match é um candidato; ele ainda precisa passar todas as
  validações abaixo. O modo é opt-in e tem budget/deadline próprios.

### Invariantes mínimas

Antes de publicar um `runtime_id`:

- raízes estão em regiões pertencentes à sessão e compatíveis com o perfil;
- todo ponteiro lido é alinhado quando o ABI exige e cai em região legível;
- `num_elements <= max_elements <= hard_limit` e operações de multiplicação/
  soma não transbordam;
- quantidade de chunks e índice de slot são coerentes com capacity;
- amostra limitada de slots vivos possui ponteiro de objeto, índice/serial e
  `ClassPrivate` estruturalmente válidos;
- índices e tamanhos de `FName` cabem no pool/chunk e respeitam comprimento e
  UTF-8/UTF-16 previstos pelo perfil;
- `UClass`/`UStruct` apresentam nomes válidos e cadeias de `SuperStruct`
  acíclicas dentro do limite;
- a lista de properties é acíclica e cada item possui nome, tamanho, offset,
  `array_dim` e próximo ponteiro válidos;
- `offset + element_size * array_dim` não transborda e respeita o tamanho
  refletido quando este for conhecido.

Falhar uma invariante obrigatória rejeita o contexto. Falhas em uma amostra
opcional reduzem confiança e são reportadas, sem serem escondidas.

`confidence: high` exige perfil vinculado à build e todas as invariantes
obrigatórias. `signature_candidate` não atinge `high` sem uma segunda evidência
independente e validação integral.

## Consistência de snapshot

O runtime pode adicionar/remover objetos durante a enumeração. Cada sweep:

1. lê um cabeçalho/epoch lógico (counts e roots);
2. captura, para cada slot da página, `(object_index, serial, object_pointer)`;
3. percorre e valida uma página limitada;
4. relê os mesmos tuples e o cabeçalho;
5. aceita a página somente se cabeçalho e digest/tuples permanecerem iguais.

Comparar apenas counts/roots é insuficiente: um slot pode ser reutilizado com a
mesma contagem. Há no máximo duas tentativas por página por padrão, limitadas
pela policy. Se o alvo continuar mudando, um job termina
`failed/unstable_snapshot` e descarta o novo draft inteiro; uma query curta
retorna `io_error` com `reason: "unstable_snapshot"`. Nenhum catálogo/contexto
parcial é publicado e o último snapshot imutável válido permanece intacto.
Retry nunca ignora cancelamento nem reinicia trabalho além da deadline.

## Contratos de domínio

```cpp
struct UnrealClassSummary {
    Address class_address{};
    std::string name;
    std::optional<Address> super_address;
    std::optional<std::string> super_name;
    std::size_t property_count{};
};

struct UnrealPropertyInfo {
    Address metadata_address{};
    std::string name;
    std::string reflected_kind;
    std::uint64_t offset_internal{};
    std::uint64_t element_size{};
    std::uint64_t array_dim{};
    std::uint64_t flags{};
    RuntimeConfidence confidence{};
    std::vector<Evidence> evidence;
};

struct UnrealRuntimeType {
    UnrealClassSummary type;
    std::vector<UnrealPropertyInfo> declared_properties;
    std::vector<UnrealPropertyInfo> inherited_properties;
    Provenance provenance;
    bool truncated{};
    std::vector<StopReason> stop_reasons;
};

struct UnrealObjectSummary {
    std::uint64_t object_index{};
    Address object_address{};
    Address class_address{};
    std::string object_name;
    std::string class_name;
    std::optional<Address> outer_address;
};

enum class UnrealRuntimePhase {
    locating_roots,
    validating_roots,
    enumerating_slots,
    building_catalog,
    publishing
};

struct UnrealRuntimeProgress {
    std::uint64_t sequence{};
    UnrealRuntimePhase phase{};
    std::size_t slots_visited{};
    std::size_t slots_eligible{};
    std::size_t objects_found{};
    std::size_t objects_stored{};
    std::size_t classes_validated{};
    std::size_t properties_validated{};
    std::size_t retries{};
};

using UnrealRuntimeJobResult = std::variant<
    UnrealRuntimeContext,
    std::vector<UnrealObjectSummary>>;
```

Catálogos são ordenados deterministicamente: classes por nome + endereço,
properties por offset + nome e objetos por `object_index`. Sets de visitados
usam limites antes de alocar.

## API MCP

As tools desta seção são propostas e não devem aparecer na tabela de recursos
implementados até que código e testes sejam entregues.

### `memory_debug.unreal_runtime_discover`

Inicia sempre um job, inclusive em modo explícito, para manter um único ciclo
de cancelamento e publicação atômica:

```json
{
  "session_id": "…",
  "module": "Game-Win64-Shipping.exe",
  "profile_id": "ue5-fproperty-profile-1",
  "mode": "explicit",
  "roots": {
    "gu_object_array_rva": "0x01234560",
    "fname_pool_rva": "0x02345670"
  },
  "deadline_ms": 10000
}
```

Em `mode: "explicit"`, `roots` usa `oneOf`: o par de RVAs acima ou o par
`gu_object_array_address`/`fname_pool_address`. Não mistura formas. RVAs exigem
`module`; endereços absolutos ficam vinculados à sessão corrente e produzem
`root_origin: "explicit_address"`.

Resposta imediata:

```json
{
  "ok": true,
  "data": {
    "job_id": "…",
    "job_kind": "unreal_runtime",
    "operation": "discover",
    "state": "queued"
  }
}
```

O cliente usa `memory_debug.job_status/results/cancel/release` com o mesmo
`session_id`. O resultado terminal de `job_results` contém o envelope comum e
o recurso publicado:

```json
{
  "ok": true,
  "data": {
    "job_id": "…",
    "job_kind": "unreal_runtime",
    "operation": "discover",
    "result": {
      "runtime_id": "…",
      "profile_id": "ue5-fproperty-profile-1",
      "module": "Game-Win64-Shipping.exe",
      "roots": {
        "gu_object_array": "0x7FF701234560",
        "fname_pool": "0x7FF702345670",
        "origin": "explicit_rva"
      },
      "confidence": "high",
      "source": "unreal:runtime-reflection",
      "evidence": ["module_fingerprint", "object_array_invariants", "name_pool_invariants"],
      "failed_invariants": []
    },
    "termination": {
      "stop_reason": "operation_completed",
      "coverage_complete": true,
      "results_complete": true,
      "complete": true,
      "truncated": false,
      "truncation_reasons": []
    }
  }
}
```

Em `auto`, a requisição também exige budgets de bytes/candidatos. Nenhum
candidato válido retorna `not_found`; perfil desconhecido retorna
`unsupported` com reason `unsupported_profile`; snapshot mutável além do retry
termina o job `failed/unstable_snapshot` e não publica `runtime_id`.

### `memory_debug.unreal_runtime_classes`

```json
{
  "session_id": "…",
  "runtime_id": "…",
  "name_contains": "Player",
  "limit": 100,
  "page_token": null
}
```

Retorna summaries, `next_page_token`, `snapshot_status`, proveniência e
coverage. O token é opaco, vinculado a runtime/process identity/filtros e
expira com o contexto. Nunca é apenas um índice confiado do cliente.

### `memory_debug.unreal_runtime_type`

```json
{
  "session_id": "…",
  "runtime_id": "…",
  "class_address": "0x000001D42A100000",
  "include_inherited": true,
  "max_properties": 256,
  "max_super_depth": 32
}
```

`class_address` deve pertencer ao catálogo validado do contexto; como
alternativa exclusiva, `class_name` seleciona uma classe e retorna
`invalid_argument` com reason `ambiguous` se houver mais de uma. A resposta
diferencia properties declaradas e herdadas, informa a classe declarante e
nunca chama uma função do objeto.

### `memory_debug.unreal_runtime_objects`

Enumeração extensa é um job paginado:

```json
{
  "session_id": "…",
  "runtime_id": "…",
  "class_name": "BP_PlayerState_C",
  "include_derived": true,
  "max_objects": 10000,
  "deadline_ms": 30000
}
```

A resposta imediata contém `job_id`, `job_kind: "unreal_runtime"`,
`operation: "objects"` e `state`. Resultados são paginados por
`memory_debug.job_results`, contêm apenas summaries — não valores de
propriedades — e usam `items/page/termination` da Spec 0008. Progresso inclui
`slots_visited`, `slots_eligible`, `objects_found`, `objects_stored`, retries e
contagem de slots instáveis.

### `memory_debug.unreal_runtime_release`

```json
{"session_id":"…","runtime_id":"…"}
```

```json
{"ok":true,"data":{"runtime_id":"…","released":true}}
```

Release invalida o contexto e libera catálogos derivados quando o último
reader COW termina. Se existe job dependente ativo, retorna `invalid_state`
com reason `resource_busy`; o cliente usa `job_cancel`, aguarda o terminal e
tenta release novamente. É idempotente para o mesmo owner durante tombstone
curto. Todas
as tools de runtime exigem o par `session_id` + `runtime_id`; owner divergente
retorna `not_found` e o ID isolado nunca funciona como capability bearer.

### Erros

Esta proposta segue o mapeamento de `DebugErrorCode` da Spec 0008:

- `unsupported` com `reason: unsupported_profile|feature_disabled`;
- `invalid_argument` com `reason: ambiguous|conflicting_roots`;
- `invalid_state` com `reason: stale_context|context_expired|resource_busy`;
- `not_found` para owner/context/classe/root ausente, sem revelar outro owner;
- `limit_exceeded` para catálogo, profundidade, job ou quota;
- `io_error` com `reason: unstable_snapshot|short_read` em query curta;
- jobs usam `state: failed` + `stop_reason` tipado, não inventam novo error code.

### Proveniência comum

Toda resposta derivada inclui:

```json
{
  "source": "unreal:runtime-reflection",
  "confidence": "medium",
  "profile_id": "…",
  "process_fingerprint": "…",
  "root_origin": "signature_candidate",
  "evidence": [],
  "failed_invariants": [],
  "snapshot_status": "stable"
}
```

`process_fingerprint` é um identificador não reversível/serializado para
comparação, não um dump de paths ou bytes do módulo.

## Limites e segurança

Policies independentes e com teto rígido:

| Limite | Padrão inicial sugerido |
|---|---:|
| slots visitados por job | 1.000.000 |
| objetos armazenados | 10.000 |
| classes armazenadas | 20.000 |
| contexts por sessão / globais | 2 / 8 |
| bytes retidos por context | 64 MiB; hard cap 256 MiB |
| TTL de context | 15 min |
| properties por tipo | 1.024 |
| profundidade de `SuperStruct` | 64 |
| nós numa cadeia de properties | 4.096 |
| bytes de um nome | 1.024 |
| retries por página | 2 |
| candidatos de roots | 64 |

Os valores definitivos dependem de benchmark e threat review. Counts do alvo
nunca causam `reserve` antes de serem validados contra esses limites. Toda
lista encadeada tem detecção de ciclos, profundidade e deadline. Toda leitura
é limitada à região e trata short-read como evidência de instabilidade/erro,
nunca como bytes zerados.

O modo default é somente leitura. A feature respeita allowlists de processo,
usuário e sessão; não altera `ARGOS_MCP_ALLOW_WRITE`. Descoberta não percorre
arquivos nem módulos fornecidos por path arbitrário. Nenhuma signature, nome,
endereço, propriedade ou byte do processo entra no log.

A implementação nasce atrás de controles server-side, todos aplicados antes
de I/O/alocação:

- `ARGOS_MCP_ENABLE_UNREAL_RUNTIME=0` por padrão;
- allowlist de `profile_id` configurada pelo operador;
- `ARGOS_MCP_ENABLE_UNREAL_AUTO_DISCOVERY=0` por padrão, independente do gate
  geral.

O cliente pode escolher apenas um perfil já habilitado e nunca ativa um gate
por argumento. Roots explícitas/profile continuam indisponíveis quando o gate
geral está desligado; `mode: auto` também exige o segundo gate. Contexts,
catálogos e jobs contam simultaneamente contra quotas por sessão e globais.

Valores de fields/instâncias ficam fora da resposta. O cliente pode fazer uma
leitura posterior do endereço calculado apenas pelas tools e policies já
existentes, preservando autorização, limites e auditabilidade.

## Observabilidade

Eventos estruturados em `stderr`, sem conteúdo sensível:

- `unreal_runtime_discovery_started/completed` com job/context ID, profile,
  origem, duração, bytes e contagens;
- `unreal_runtime_page_completed` com slots visitados/aceitos, retries e estado
  de snapshot;
- `unreal_runtime_validation_failed` com código de invariante, nunca endereço
  ou bytes;
- `unreal_runtime_context_released/expired` com motivo.

Métricas: throughput de slots, reads/bytes nativos, classes/properties válidas,
taxa de slots mortos, retries, snapshots instáveis, candidatos rejeitados e
memória derivada retida. `stdout` permanece exclusivamente JSON-RPC/MCP.

## Performance e lifetime

- chunks de `GUObjectArray` são lidos em blocos limitados e reutilizados;
- nomes podem usar cache bounded por índice + generation do pool;
- classes/properties validadas usam snapshot imutável/COW publicado somente ao
  concluir uma geração;
- queries nunca mantêm locks durante I/O;
- cancelamento é observado entre reads, slots e nós de listas;
- jobs usam o pool possuído/joinable do `AnalysisJobManager`; não há thread ou
  pool Unreal separado;
- `detach` cancela jobs, invalida contexts e faz join antes de liberar a
  sessão; shutdown segue a mesma ordem;
- falha de uma reconstrução preserva o último catálogo válido, mas o marca
  stale se a identidade não puder mais ser comprovada.

## Plano de testes

### Unitários do parser

Golden fixtures sintéticas, sem dump proprietário:

- ao menos um perfil `FField/FProperty` moderno com classe base, classe
  derivada e um campo `Credits` em offset conhecido (incluindo `+0x590` como
  caso de regressão, não como constante do produto);
- um perfil legado separado se `UProperty` entrar no primeiro release;
- `GUObjectArray` chunked com slot vivo, slot morto e fronteira de chunk;
- `FNamePool` ANSI/UTF conforme o perfil, índice inválido, comprimento hostil e
  nome cruzando limite;
- classe, herança, outer e lista de properties válidos;
- ciclos em `SuperStruct`, property next e outer;
- counts/capacity hostis, ponteiro desalinhado, região ilegível, short-read e
  overflow em endereço/tamanho/offset;
- `element_size * array_dim`, offset negativo/incompatível conforme o perfil;
- mutação entre primeira e segunda leitura produz retry e depois
  `unstable_snapshot`;
- reutilização de slot altera pointer/serial com counts constantes e ainda é
  detectada pelo digest/segunda leitura;
- cancelamento em cada loop relevante e teardown sem use-after-free;
- perfil desconhecido/incompatível nunca tenta offsets de outro perfil.

Fuzz/property tests alimentam headers, `FName` e listas sintéticas sob
ASan/UBSan. TSan cobre publicação COW, query concorrente, cancelamento e
detach.

### Contrato MCP

- tools aparecem apenas quando feature e ao menos um perfil estão habilitados;
- schemas impõem exclusividade entre roots explícitas e auto discovery;
- endereços são hex strings e counts nunca dependem de precisão JSON number;
- paginação mantém ordem, filtros e tokens vinculados ao contexto;
- starts/controles usam `job_kind: unreal_runtime` e as quatro tools genéricas;
- todas as queries/release exigem owner `session_id + runtime_id`;
- gates geral/auto, allowlist de profile, quotas e TTL são impostos pelo
  servidor e não podem ser ligados pelo request;
- proveniência/confiança/evidência aparecem em sucesso e resultado parcial;
- payload respeita caps e `unstable_snapshot` não é serializado como complete;
- clientes MCP legado e 2026 recebem o envelope apropriado.

### Integração opcional

Um target Unreal Development controlado pelo projeto pode emitir ground truth
e ser executado com PDB removido/indisponível. O teste compara classes,
herança e offsets runtime com esse manifesto. Dumps de jogos proprietários não
entram no repositório nem no CI.

## Critérios de aceite

- uma fixture moderna enumera `GUObjectArray`, resolve nomes/classes e retorna
  `FProperty` com offsets corretos sem PDB;
- nenhuma classe/property recebe confiança alta sem todas as invariantes do
  perfil e da build;
- perfil desconhecido ou root apenas plausível falha de modo seguro;
- snapshot mutável nunca mistura silenciosamente duas gerações;
- paginação e limites mantêm memória/resposta bounded mesmo com counts hostis;
- `job_release` e `unreal_runtime_release` têm lifecycles distintos; TTL e
  detach liberam contexts sem UAF;
- cancelamento, detach e shutdown não deixam worker nem contexto vivo;
- código de domínio não inclui JSON, DbgHelp, Win32 ou Linux;
- não há escrita, injeção, chamada remota ou exposição automática de valores;
- logs não contêm nomes, endereços ou bytes do processo;
- PDB e runtime permanecem fontes separadas e comparáveis.

## Entrega incremental

1. porta de leitura, tipos, profiles e fixtures sintéticas;
2. modo `explicit` para `GUObjectArray` + `FNamePool`;
3. classes, herança e `FProperty` paginadas;
4. objetos filtrados e snapshot retry;
5. perfil/build roots e validação de fingerprint;
6. descoberta `auto` multipadrão, ainda opt-in;
7. integração opcional com target Unreal próprio e habilitação documentada.

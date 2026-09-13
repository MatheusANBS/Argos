# Arquitetura

## Objetivo

Expor operações limitadas de depuração de memória como tools MCP sem acoplar o domínio a JSON-RPC, `stdio` ou APIs nativas.

## Camadas

### Domain

Contém tipos fortes, erros tipados e as interfaces `ProcessSession` e `ProcessMemoryProvider`. Não conhece JSON, MCP, logging ou sistema operacional.

### Application

`MemoryDebugService` aplica casos de uso, limites e coordena sessões. `SessionManager` mantém handles opacos explícitos, permitindo que chamadas MCP sejam independentes do PID bruto após o attach.

### Security

`SecurityPolicy` centraliza autorização, limites e gates de escrita. Variáveis de ambiente são lidas apenas na composição do executável.

### Infrastructure

`NativeProcessMemoryProvider` implementa as portas do domínio com Win32 ou Linux. Handles e sessões são RAII.

### Protocol/MCP

`ToolCatalog` valida JSON, converte argumentos em tipos internos, delega ao serviço e apresenta respostas seguras. `Server` implementa o dispatcher JSON-RPC e o transporte `stdio` linha a linha.

O dispatcher seleciona o contrato por requisição: metadados reservados ativam
o MCP sem estado `2026-07-28`; na ausência deles, `initialize`/`ping` e os
envelopes `2025-11-25`/`2025-06-18` permanecem disponíveis (ADR-0016).

## Dependências

```text
argos_runtime_memory_mcp
        ↓
argos_protocol
        ↓
argos_application
        ↓
argos_domain
        ↑
argos_infrastructure
```

`argos_application` recebe `ProcessMemoryProvider` por injeção. Isso permite testes sem anexar processos reais.

## Concorrência

O transporte aceita uma tool ativa por vez. A tool roda em `std::jthread`, enquanto a thread de leitura continua recebendo `notifications/cancelled`. Scans verificam `std::stop_token` entre chunks; chamadas adicionais recebem `Server busy` até a operação terminar. `SessionManager` usa mutex e retorna `shared_ptr` porque uma operação pode continuar usando a sessão depois que o lock é liberado. `detach` remove a sessão do registry; operações que já obtiveram uma referência podem terminar com segurança.

## Metadados de tipos

`MemoryDebugService` tambem recebe `TypeMetadataProvider`. No Windows,
`PdbTypeMetadataProvider` consulta DbgHelp no processo do MCP e so aceita o
modulo que ja foi listado na sessao. O cliente nao fornece um caminho de PDB
arbitrario. DbgHelp e protegido por mutex porque a API oficial nao e
thread-safe.

## Adapters de runtime específicos de engine

O suporte aprovado Santa Monica/Kinetica (ADR-0022 / Spec 0014) preserva a
mesma direção de dependências. O domínio recebe leitores e canais de bridge
tipados, enquanto a infraestrutura Windows contém PE, carga antecipada/attach,
assinaturas, RTTI, SLI, Lua e ABI nativa. A camada MCP só valida e apresenta
handles opacos. O adapter é orientado a perfis exatos de build, nunca a
endereços ou assinaturas fornecidos pelo cliente.

O primeiro incremento já implementa `domain::santamonica::ReflectionCatalog`
e a porta `SantaMonicaRuntimeReader`: admissão integral de registros
normalizados com identidade, limites e validação de referências. O catálogo
possui seus dados e é publicado como `unique_ptr<const ...>`; a validação usa
índices temporários ordenados, sem threads, JSON ou OS. O reader sintético dos
testes não é distribuído como adapter nativo nem atesta autenticação de bridge.

O segundo incremento acrescenta a infraestrutura do snapshot (ADR-0023):
`encode_reflection_frame` e `ReflectionStreamReader` traduzem frames binários
versionados para os registros tipados do domínio. O codec vive fora do domínio,
não usa JSON, MCP nem API de SO, não cria threads e não serializa structs
nativas. A porta `ReflectionByteStream` isola o transporte, que ainda não
existe: autenticação, ACL e bootstrap permanecem responsabilidade da futura
fábrica nativa, não do codec.

O terceiro incremento acrescenta o handshake (ADR-0024) com a mesma direção de
dependências: o domínio possui segredo, transcript, verificação em tempo
constante e a máquina de estados de uso único, expondo as portas
`MessageAuthenticator` e `RandomSource`; a infraestrutura implementa essas
portas com o provedor do sistema (CNG) e acrescenta o enquadramento `SMBH`.
Nenhuma primitiva criptográfica é escrita neste repositório, o domínio
continua sem OS, relógio ou bytes de transporte, e os dois codecs compartilham
as primitivas internas de bytes em `src/infrastructure/detail/wire_bytes.hpp`.

O quarto incremento fecha a pilha na mesma direção: a infraestrutura acrescenta
`LocalBridgeChannel` (named pipe com ACL, deadlines e verificação do par),
`BridgePeerProcess` (lançamento do peer com bootstrap do segredo por stdin) e os
drivers de sessão dos dois lados; a aplicação ganha `SantaMonicaRuntimeManager`,
com quotas, TTL e um único dono por instância/época, além dos casos de uso em
`memory_debug_service_santamonica.cpp`; a camada MCP só valida entrada, pagina
com tokens opacos e serializa. O domínio permanece sem Win32, JSON ou MCP, e o
peer controlado (`tools/santa_monica_peer.cpp`) é um executável separado que
consome as mesmas portas — ele não é linkado ao servidor nem fala com o jogo.

O `SantaMonicaRuntimeManager` proposto possui snapshots imutáveis, handles por
geração e registros de mutação com deduplicação e resultado incerto. Ele não
encaminha gameplay ao `AnalysisJobManager`, cujo contrato é de scans. Um único
owner por processo/época serializa engine e Lua. O canal da bridge exige
handshake autenticado e framing limitado, ainda ausentes na bridge de presença
da Spec 0013. Release fecha admissão e cancela fila; callbacks ativos conservam
estado até cleanup seguro, sem unload e sem espera local ilimitada pelo alvo.

O caminho nativo da ADR-0027 implementa a mesma porta, lendo tabelas de tipos,
atributos, enums e SLI pela sessão autorizada. A infraestrutura resolve índices
de dono/base/enum e normaliza os registros; o domínio continua sem JSON ou OS.
Faixas de atributos selecionam declarações próprias sem seguir arrays de membros
no heap. Ponteiros/coleções podem ter alvo sem tipo refletido, mas objetos
embutidos exigem referência e tamanho exatos. Toda referência fornecida é validada
pelo catálogo. A aplicação propaga todas as faixas do perfil e calcula sua identidade.

O inventário de recursos da ADR-0028 segue a mesma divisão. O domínio
(`santa_monica_inventory`) define entradas por valor, validação UTF-8 dos nomes
e a admissão de quantidade para escrita, sem OS nem JSON. A infraestrutura
(`santa_monica_inventory_reader`) segue a raiz do perfil até o store, valida
`ResourcesPerm`, ligações e estados em duas passadas estruturais e localiza o
slot de um recurso, sem jamais escrever. A aplicação guarda o snapshot em cache
no contexto publicado, com lock apenas na troca do ponteiro, e faz a escrita
direta pela sessão `read_write` com revalidação e releitura. A camada MCP expõe
`santamonica_runtime_resources` e `santamonica_runtime_set_resource` somente
quando algum perfil publica a raiz.

## Shutdown

Fechamento de `stdin` encerra o loop. A destruição em ordem reversa libera sessions, handles e demais objetos. Não existem threads destacadas.

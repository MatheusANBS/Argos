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

O suporte proposto Santa Monica/Kinetica (ADR-0022 / Spec 0014) preserva a
mesma direção de dependências. O domínio recebe leitores e canais de bridge
tipados, enquanto a infraestrutura Windows contém PE, carga antecipada/attach,
assinaturas, RTTI, SLI, Lua e ABI nativa. A camada MCP só valida e apresenta
handles opacos. O adapter é orientado a perfis exatos de build, nunca a
endereços ou assinaturas fornecidos pelo cliente.

## Shutdown

Fechamento de `stdin` encerra o loop. A destruição em ordem reversa libera sessions, handles e demais objetos. Não existem threads destacadas.

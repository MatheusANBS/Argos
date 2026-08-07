# ADR-0002 — Sessões explícitas e autorização

Status: aceito

## Contexto

Reutilizar PID diretamente em cada tool facilitaria chamadas acidentais e dificultaria controlar access mode e lifetime do handle.

## Decisão

`memory_debug.attach` exige `authorized: true` e retorna um `session_id` opaco. Todas as operações posteriores usam esse handle. O servidor restringe processos ao mesmo usuário por padrão. Escrita depende de configuração no startup, sessão `read_write` e confirmação por chamada.

## Consequências

- melhor rastreabilidade e encapsulamento;
- handles são liberados por `detach` ou shutdown;
- sessões não sobrevivem ao processo MCP;
- clientes devem guardar e reutilizar o `session_id`.

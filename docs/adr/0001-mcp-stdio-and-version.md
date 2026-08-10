# ADR-0001 — MCP estável via stdio

Status: aceito

## Contexto

O servidor precisa funcionar como processo local, com superfície mínima de rede e integração simples com clientes MCP.

## Decisão

Implementar JSON-RPC 2.0 sobre `stdio`, negociando `2025-11-25` e aceitando `2025-06-18` para compatibilidade. `stdout` contém somente protocolo; logs estruturados usam `stderr`.

A ADR-0016 amplia esta decisão com o modo sem estado `2026-07-28`,
preservando integralmente a negociação legada descrita acima.

## Consequências

- reduz superfície de rede e autenticação;
- cada cliente inicia seu próprio processo servidor;
- o codec JSON é interno e testado;
- Streamable HTTP fica fora do escopo desta versão.

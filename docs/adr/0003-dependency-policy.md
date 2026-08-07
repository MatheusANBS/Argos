# ADR-0003 — Sem dependências de runtime

Status: aceito

## Contexto

SDKs C++ de MCP e bibliotecas JSON adicionariam supply-chain, versionamento e disponibilidade desigual entre MSVC, Clang e GCC.

## Decisão

Implementar apenas o subconjunto JSON-RPC/MCP necessário e um codec JSON interno. Usar somente biblioteca padrão e APIs nativas do sistema operacional.

## Consequências

- build reproduzível e simples;
- menor superfície de supply-chain;
- responsabilidade local por testes de parser e compatibilidade;
- extensões futuras do MCP exigem atualização explícita.

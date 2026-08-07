---
name: cpp-toolchain
description: Toolchain e análise para o projeto Argos Runtime Memory MCP.
---

# Toolchain e análise

Suporte MSVC, Clang e GCC quando possível. Ative warnings altos, permissive- no MSVC, clang-tidy opcional, clang-format e builds separadas de ASan/UBSan e TSan. Não desative warnings globalmente para acomodar código próprio ou dependências.

## Processo obrigatório

1. Ler arquitetura, ADRs e threat model relevantes.
2. Declarar invariantes, ownership e política de erros.
3. Implementar a menor mudança coerente com as camadas.
4. Adicionar testes e casos de falha.
5. Compilar com warnings elevados e executar sanitizers aplicáveis.
6. Atualizar documentação e registrar trade-offs.

## Definition of Done

- C++23 explícito;
- sem warnings novos;
- ownership e lifetime claros;
- sem `new`/`delete` direto sem justificativa;
- testes unitários e de contrato passando;
- erros externos traduzidos para mensagens seguras;
- sem segredos em logs;
- revisão arquitetural e de segurança concluída.

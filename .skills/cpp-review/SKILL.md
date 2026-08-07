---
name: cpp-review
description: Revisão final C++ para o projeto Argos Runtime Memory MCP.
---

# Revisão final C++

Antes de concluir, revise warnings, UB, exceções, lifetime, bounds, overflow, concorrência, cancelamento, shutdown, testes, sanitizers, segurança, logs e impacto arquitetural. Confirme que stdout não contém logs, escrita segue desabilitada por padrão e não há achados críticos ou altos.

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

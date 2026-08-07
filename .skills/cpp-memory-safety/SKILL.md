---
name: cpp-memory-safety
description: Segurança de memória para o projeto Argos Runtime Memory MCP.
---

# Segurança de memória

Revise ownership, lifetime, bounds, invalidation, overflow de endereços, alinhamento, short reads/writes, double-free, UAF, leaks e UB. Todo handle, arquivo, socket e sessão deve possuir wrapper RAII. Ponteiros crus são não proprietários e devem ficar restritos a fronteiras nativas.

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

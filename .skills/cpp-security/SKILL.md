---
name: cpp-security
description: Segurança de C++ e MCP para o projeto Argos Runtime Memory MCP.
---

# Segurança de C++ e MCP

Valide toda entrada externa. Revise overflow inteiro, buffer overflow, path traversal, command injection, desserialização insegura, supply chain e exposição de segredos. Para memória de processos, exija autorização explícita, mesmo usuário por padrão, limites rígidos, escrita desabilitada por padrão e erros seguros.

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

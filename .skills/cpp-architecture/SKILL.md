---
name: cpp-architecture
description: Arquitetura C++ em camadas para o projeto Argos Runtime Memory MCP.
---

# Arquitetura C++ em camadas

Defina targets e dependências na direção Executable → Protocol/MCP → Application → Domain, com infraestrutura implementando portas do domínio. Proíba JSON, MCP, transporte, filesystem, logging e APIs de SO no domínio. Revise ciclos, responsabilidade, composição e limites de módulos.

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

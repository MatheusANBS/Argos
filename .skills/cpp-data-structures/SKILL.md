---
name: cpp-data-structures
description: Estruturas de dados para o projeto Argos Runtime Memory MCP.
---

# Estruturas de dados

Escolha estruturas pelo padrão real de acesso, tamanho, estabilidade, cache locality, concorrência e custo de alocação. Prefira vector para sequências, array para tamanho fixo, unordered_map para lookup médio e map quando ordenação/estabilidade forem requisitos. Use variant para estados exclusivos e expected para falhas recuperáveis.

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
